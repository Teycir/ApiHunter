// src/threat_intel/mod.rs
//
// Public surface for the threat-intel module.
//
// This module fires lightweight passive probes (InternetDB, ipinfo.io, RDAP)
// against a list of hosts and scores them by risk. It is the engine powering
// the `enrich` subcommand / Enrich Mode in the desktop app.
//
// Design constraints
// ──────────────────
// • No hidden exceptions: every error is either propagated as a typed
//   ProbeError (fatal, engine-level) or recorded as a per-entry signal/error
//   string (non-fatal, target-level). Nothing is silently swallowed.
// • Fully decoupled from the scanner pipeline: no dependency on Config,
//   runner, or any scanner module.
// • run_probes() is the single public entry point.

pub mod resolver;
pub mod risk;
pub mod sources;
pub mod types;

use std::sync::Arc;
use std::time::Instant;

use futures::StreamExt;
use thiserror::Error;

use crate::threat_intel::{
    resolver::is_ip,
    risk::compute_risk_score,
    sources::{internetdb, ipinfo, rdap},
    types::{SourceOutcome, ThreatIntelConfig, ThreatIntelEntry, ThreatIntelResult},
};

// ── Engine-level errors ───────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("failed to build HTTP client for threat-intel probes: {0}")]
    ClientBuild(#[from] reqwest::Error),

    #[error("threat-intel probes require at least one target")]
    NoTargets,

    #[error("task join error during probing: {0}")]
    Join(#[from] tokio::task::JoinError),
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run threat-intel probes over `targets`.
///
/// Returns `Err(ProbeError)` only for engine-level failures.
/// Per-target probe errors are non-fatal and recorded in `ThreatIntelResult::errors`.
pub async fn run_probes(
    targets: Vec<String>,
    config: ThreatIntelConfig,
) -> Result<ThreatIntelResult, ProbeError> {
    if targets.is_empty() {
        return Err(ProbeError::NoTargets);
    }

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(config.timeout * 3)
            .user_agent("ApiHunter-ThreatIntel/1.0")
            .build()
            .map_err(ProbeError::ClientBuild)?,
    );

    let config = Arc::new(config);
    let engine_start = Instant::now();

    let results: Vec<Result<ThreatIntelEntry, (String, String)>> =
        futures::stream::iter(targets)
            .map(|target| {
                let client = Arc::clone(&client);
                let config = Arc::clone(&config);
                async move { probe_target(target, &client, &config).await }
            })
            .buffer_unordered(config.concurrency)
            .collect()
            .await;

    let elapsed_ms = engine_start.elapsed().as_millis() as u64;

    let mut entries: Vec<ThreatIntelEntry> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for r in results {
        match r {
            Ok(entry) => {
                if entry.score >= config.min_score {
                    entries.push(entry);
                }
            }
            Err((target, msg)) => {
                errors.push(format!("{target}: {msg}"));
            }
        }
    }

    entries.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));

    let total = entries.len();
    if config.top_n > 0 && entries.len() > config.top_n {
        entries.truncate(config.top_n);
    }

    Ok(ThreatIntelResult {
        entries,
        total,
        elapsed_ms,
        errors,
    })
}

// ── Per-target probe ──────────────────────────────────────────────────────────

async fn probe_target(
    target: String,
    client: &reqwest::Client,
    config: &ThreatIntelConfig,
) -> Result<ThreatIntelEntry, (String, String)> {
    let probe_start = Instant::now();

    let (ip, domain) = resolve_target(&target, client, config).await;
    let ip_ref = ip.as_deref().unwrap_or("");

    let (idb_outcome, ipinfo_outcome) = if ip_ref.is_empty() {
        (SourceOutcome::Skipped, SourceOutcome::Skipped)
    } else {
        tokio::join!(
            internetdb::fetch(ip_ref, client, config.timeout),
            ipinfo::fetch(ip_ref, client, config.timeout),
        )
    };

    let rdap_outcome = if let Some(ref dom) = domain {
        rdap::fetch(dom, client, config.timeout).await
    } else {
        SourceOutcome::Skipped
    };

    log_source_outcome("internetdb", ip_ref, &idb_outcome);
    log_source_outcome("ipinfo", ip_ref, &ipinfo_outcome);
    if let Some(ref dom) = domain {
        log_source_outcome("rdap", dom, &rdap_outcome);
    }

    let risk = compute_risk_score(
        idb_outcome.as_ref(),
        ipinfo_outcome.as_ref(),
        rdap_outcome.as_ref(),
    );

    let mut signals = risk.signals;
    annotate_outcome_signal("internetdb", &idb_outcome, &mut signals);
    annotate_outcome_signal("ipinfo", &ipinfo_outcome, &mut signals);
    annotate_outcome_signal("rdap", &rdap_outcome, &mut signals);

    let ports = idb_outcome.as_ref().map(|d| d.ports.clone()).unwrap_or_default();
    let cve_ids = idb_outcome.as_ref().map(|d| d.vulns.clone()).unwrap_or_default();
    let asn = ipinfo_outcome.as_ref().and_then(|d| d.asn());
    let country = ipinfo_outcome.as_ref().and_then(|d| d.country.clone());
    let domain_age_days = rdap_outcome.as_ref().and_then(|d| d.age_days());
    let response_ms = probe_start.elapsed().as_millis() as u64;

    Ok(ThreatIntelEntry {
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

async fn resolve_target(
    target: &str,
    client: &reqwest::Client,
    config: &ThreatIntelConfig,
) -> (Option<String>, Option<String>) {
    let host = extract_host(target);
    if is_ip(host) {
        (Some(host.to_string()), None)
    } else {
        let ip = resolver::resolve(host, client, config.timeout).await;
        if ip.is_none() {
            tracing::debug!(target, host, "DoH resolution returned no result");
        }
        (ip, Some(host.to_string()))
    }
}

fn extract_host(target: &str) -> &str {
    let s = target
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split(':').next().unwrap_or(s);
    s.trim()
}

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
