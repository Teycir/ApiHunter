// src/triage/mod.rs
//
// Public surface for the triage module.
//
// Design constraints
// ──────────────────
// • No hidden exceptions: every error that occurs during probing is either
//   propagated as a typed TriageError (fatal, engine-level) or recorded as a
//   per-entry signal/error string (non-fatal, target-level).  Nothing is
//   silently swallowed.
// • Fully decoupled from the scanner pipeline: shares only the reqwest client
//   construction pattern; no dependency on Config, runner, or any scanner.
// • run_triage() is the single public entry point.  Callers get back a
//   Result<TriageResult, TriageError> — they always know when something went
//   wrong at the engine level.

pub mod resolver;
pub mod risk;
pub mod sources;
pub mod types;

use std::sync::Arc;
use std::time::Instant;

use futures::StreamExt;
use thiserror::Error;

use crate::triage::{
    resolver::is_ip,
    risk::compute_risk_score,
    sources::{internetdb, ipinfo, rdap},
    types::{SourceOutcome, TriageConfig, TriageEntry, TriageResult},
};

// ── Engine-level errors ───────────────────────────────────────────────────────

/// Fatal errors that prevent the triage engine from running at all.
/// Per-target probe failures are *not* represented here — they are captured
/// inside TriageResult::errors and as per-entry signals.
#[derive(Debug, Error)]
pub enum TriageError {
    #[error("failed to build HTTP client for triage: {0}")]
    ClientBuild(#[from] reqwest::Error),

    #[error("triage requires at least one target")]
    NoTargets,

    #[error("task join error during triage: {0}")]
    Join(#[from] tokio::task::JoinError),
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run a triage pass over `targets`.
///
/// Returns `Err(TriageError)` only for engine-level failures (client build
/// error, no targets provided, catastrophic task join failure).
///
/// Per-target probe errors are non-fatal: they are recorded in
/// `TriageResult::errors` and as `signals` on the relevant `TriageEntry`.
pub async fn run_triage(
    targets: Vec<String>,
    config: TriageConfig,
) -> Result<TriageResult, TriageError> {
    if targets.is_empty() {
        return Err(TriageError::NoTargets);
    }

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(config.timeout * 3) // outer guard; inner probes use config.timeout
            .user_agent("ApiHunter-Triage/1.0")
            .build()
            .map_err(TriageError::ClientBuild)?,
    );

    let config = Arc::new(config);
    let engine_start = Instant::now();

    // Spawn one task per target, bounded by concurrency.
    let results: Vec<Result<TriageEntry, (String, String)>> = futures::stream::iter(targets)
        .map(|target| {
            let client = Arc::clone(&client);
            let config = Arc::clone(&config);
            async move { probe_target(target, &client, &config).await }
        })
        .buffer_unordered(config.concurrency)
        .collect()
        .await;

    let elapsed_ms = engine_start.elapsed().as_millis() as u64;

    let mut entries: Vec<TriageEntry> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for r in results {
        match r {
            Ok(entry) => {
                if entry.score >= config.min_score {
                    entries.push(entry);
                }
            }
            // probe_target only returns Err for truly unexpected failures
            // (e.g. a panic in a spawned task); normal probe errors are Ok.
            Err((target, msg)) => {
                errors.push(format!("{target}: {msg}"));
            }
        }
    }

    // Sort highest raw_score first — preserves ranking within severity bands
    // that the normalised score would collapse into a tie.
    entries.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));

    // Record the full count before truncation so callers know the true hit count.
    let total = entries.len();

    // Apply top-N truncation
    if config.top_n > 0 && entries.len() > config.top_n {
        entries.truncate(config.top_n);
    }

    Ok(TriageResult {
        entries,
        total,
        elapsed_ms,
        errors,
    })
}

// ── Per-target probe ──────────────────────────────────────────────────────────

/// Probe a single target and compute its risk score.
///
/// Returns `Ok(TriageEntry)` in all normal cases — probe failures are encoded
/// as signals and in the entry's score (0, severity LOW).
/// Returns `Err((target, msg))` only if a catastrophic unexpected error
/// prevents even a fallback entry from being produced.
async fn probe_target(
    target: String,
    client: &reqwest::Client,
    config: &TriageConfig,
) -> Result<TriageEntry, (String, String)> {
    let probe_start = Instant::now();

    // ── Step 1: resolve domain → IP ───────────────────────────────────────────
    let (ip, domain) = resolve_target(&target, client, config).await;

    // ── Step 2: fire probes in parallel ───────────────────────────────────────
    let ip_ref = ip.as_deref().unwrap_or("");

    let (idb_outcome, ipinfo_outcome) = if ip_ref.is_empty() {
        // No IP available — mark both probes as skipped, not silently ignored.
        (SourceOutcome::Skipped, SourceOutcome::Skipped)
    } else {
        tokio::join!(
            internetdb::fetch(ip_ref, client, config.timeout),
            ipinfo::fetch(ip_ref, client, config.timeout),
        )
    };

    // RDAP is domain-only; skip for raw IPs.
    let rdap_outcome = if let Some(ref dom) = domain {
        rdap::fetch(dom, client, config.timeout).await
    } else {
        SourceOutcome::Skipped
    };

    // ── Step 3: log non-OK outcomes so callers can diagnose probe failures ────
    log_source_outcome("internetdb", ip_ref, &idb_outcome);
    log_source_outcome("ipinfo", ip_ref, &ipinfo_outcome);
    if let Some(ref dom) = domain {
        log_source_outcome("rdap", dom, &rdap_outcome);
    }

    // ── Step 4: score ─────────────────────────────────────────────────────────
    let risk = compute_risk_score(
        idb_outcome.as_ref(),
        ipinfo_outcome.as_ref(),
        rdap_outcome.as_ref(),
    );

    // ── Step 5: augment signals with any probe-level errors ───────────────────
    let mut signals = risk.signals;
    annotate_outcome_signal("internetdb", &idb_outcome, &mut signals);
    annotate_outcome_signal("ipinfo", &ipinfo_outcome, &mut signals);
    annotate_outcome_signal("rdap", &rdap_outcome, &mut signals);

    // ── Step 6: extract structured fields ────────────────────────────────────
    let ports = idb_outcome
        .as_ref()
        .map(|d| d.ports.clone())
        .unwrap_or_default();

    let cve_ids = idb_outcome
        .as_ref()
        .map(|d| d.vulns.clone())
        .unwrap_or_default();

    let asn = ipinfo_outcome.as_ref().and_then(|d| d.asn());
    let country = ipinfo_outcome
        .as_ref()
        .and_then(|d| d.country.clone());

    let domain_age_days = rdap_outcome.as_ref().and_then(|d| d.age_days());

    let response_ms = probe_start.elapsed().as_millis() as u64;

    Ok(TriageEntry {
        target,
        resolved_ip: ip,
        score: risk.score,
        raw_score: risk.raw_score,
        severity: risk.severity,
        signals,
        has_likely_vulnerability: risk.has_likely_vulnerability,
        ports,
        cve_ids,
        asn,
        country,
        domain_age_days,
        response_ms,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolve `target` to (Option<ip>, Option<domain>).
/// Raw IPs pass through unchanged.  Domains are resolved via DoH.
/// Resolution failure is non-fatal: both fields return None.
async fn resolve_target(
    target: &str,
    client: &reqwest::Client,
    config: &TriageConfig,
) -> (Option<String>, Option<String>) {
    // Strip scheme/path to get the bare host.
    let host = extract_host(target);

    if is_ip(host) {
        (Some(host.to_string()), None)
    } else {
        // It's a domain.
        let ip = resolver::resolve(host, client, config.timeout).await;
        if ip.is_none() {
            tracing::debug!(target, host, "DoH resolution returned no result");
        }
        (ip, Some(host.to_string()))
    }
}

/// Strip scheme (http://, https://) and path/port from a target string,
/// returning the bare hostname or IP.
fn extract_host(target: &str) -> &str {
    let s = target
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    // Drop path and port
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split(':').next().unwrap_or(s);
    s.trim()
}

/// Emit a tracing event for non-OK source outcomes so nothing is silently lost.
fn log_source_outcome<T>(source: &str, host: &str, outcome: &SourceOutcome<T>) {
    match outcome {
        SourceOutcome::Ok(_) | SourceOutcome::Skipped => {}
        SourceOutcome::Timeout => {
            tracing::debug!(source, host, "probe timed out");
        }
        SourceOutcome::Error(msg) => {
            tracing::debug!(source, host, error = %msg, "probe error");
        }
    }
}

/// Push a human-readable signal describing a non-OK outcome.
fn annotate_outcome_signal<T>(source: &str, outcome: &SourceOutcome<T>, signals: &mut Vec<String>) {
    match outcome {
        SourceOutcome::Ok(_) | SourceOutcome::Skipped => {}
        SourceOutcome::Timeout => {
            signals.push(format!("{source}: timeout"));
        }
        SourceOutcome::Error(msg) => {
            signals.push(format!("{source} error: {msg}"));
        }
    }
}
