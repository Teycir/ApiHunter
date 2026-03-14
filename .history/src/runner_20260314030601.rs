//! Central orchestration layer.
//!
//! Responsibilities:
//!   1. Accept a deduplicated list of seed URLs + discovered endpoints.
//!   2. Gate the work queue against `config.max_endpoints`.
//!   3. Fan work out across a bounded Tokio worker pool (semaphore-limited).
//!   4. Run every enabled [`Scanner`] against each URL concurrently.
//!   5. Aggregate all [`Finding`]s and [`CapturedError`]s thread-safely.
//!   6. Return a [`RunResult`] ready for the reporter.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    sync::{mpsc, Semaphore},
    task::JoinSet,
};
use tracing::{debug, error, info, warn};
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    report::Finding,
    scanner::{
        api_security::ApiSecurityScanner,
        cors::CorsScanner,
        csp::CspScanner,
        graphql::GraphqlScanner,
        Scanner,                   // async trait
    },
};

// ── Public surface ─────────────────────────────────────────────────────────────

/// Everything produced by a completed run.
#[derive(Debug, Default)]
pub struct RunResult {
    /// Deduplicated, sorted list of findings across all scanners + URLs.
    pub findings: Vec<Finding>,
    /// Every non-fatal error encountered during the run.
    pub errors:   Vec<CapturedError>,
    /// Wall-clock time for the full run.
    pub elapsed:  Duration,
    /// How many URLs were actually scanned (may be < input list due to cap).
    pub scanned:  usize,
    /// How many URLs were skipped (cap or dedup).
    pub skipped:  usize,
}

/// Entry point called from `main`.
pub async fn run(config: Arc<Config>, urls: Vec<String>) -> RunResult {
    let start = Instant::now();

    // ── 1. Normalise + deduplicate ────────────────────────────────────────────
    let (unique, skipped_dedup) = dedup(urls);
    info!(
        total   = unique.len() + skipped_dedup,
        unique  = unique.len(),
        skipped = skipped_dedup,
        "URL list normalised"
    );

    // ── 2. Apply max_endpoints cap ────────────────────────────────────────────
    let (work_list, skipped_cap) = apply_cap(unique, config.max_endpoints);
    if skipped_cap > 0 {
        warn!(
            cap     = config.max_endpoints,
            skipped = skipped_cap,
            "URL list truncated to max_endpoints"
        );
    }

    let scanned = work_list.len();
    let skipped = skipped_dedup + skipped_cap;

    if scanned == 0 {
        warn!("No URLs to scan — returning empty result");
        return RunResult { elapsed: start.elapsed(), skipped, ..Default::default() };
    }

    // ── 3. Shared state ───────────────────────────────────────────────────────
    let client     = Arc::new(HttpClient::new(&config));
    let semaphore  = Arc::new(Semaphore::new(config.concurrency));
    let scanners   = build_scanners(&config);   // Arc<dyn Scanner> list

    // mpsc channels — workers send back results; main task collects
    let (finding_tx, mut finding_rx) =
        mpsc::unbounded_channel::<Vec<Finding>>();
    let (error_tx, mut error_rx) =
        mpsc::unbounded_channel::<Vec<CapturedError>>();

    // ── 4. Spawn worker tasks ─────────────────────────────────────────────────
    let mut join_set: JoinSet<()> = JoinSet::new();

    for url in work_list {
        let sem      = Arc::clone(&semaphore);
        let client   = Arc::clone(&client);
        let scanners = scanners.clone();          // Vec<Arc<dyn Scanner>>
        let ftx      = finding_tx.clone();
        let etx      = error_tx.clone();
        let cfg      = Arc::clone(&config);

        join_set.spawn(async move {
            // Acquire a concurrency slot — drops automatically at scope end
            let _permit = match sem.acquire().await {
                Ok(p)  => p,
                Err(e) => {
                    error!(url = %url, "Semaphore closed: {e}");
                    return;
                }
            };

            scan_url(url, &client, &scanners, &cfg, ftx, etx).await;
        });
    }

    // Drop the sender halves we kept in main; workers hold their own clones.
    // Once all workers finish, the channels will drain.
    drop(finding_tx);
    drop(error_tx);

    // ── 5. Collect results while workers run ──────────────────────────────────
    // Drive workers to completion while simultaneously draining channels to
    // avoid backpressure stalling the unbounded senders (belt-and-suspenders).
    let mut findings: Vec<Finding>       = Vec::new();
    let mut errors:   Vec<CapturedError> = Vec::new();

    loop {
        tokio::select! {
            biased;

            Some(batch) = finding_rx.recv() => {
                findings.extend(batch);
            }
            Some(batch) = error_rx.recv() => {
                errors.extend(batch);
            }
            result = join_set.join_next() => {
                match result {
                    Some(Ok(())) => {}
                    Some(Err(e)) => error!("Worker task panicked: {e}"),
                    None         => break,   // JoinSet exhausted
                }
            }
        }
    }

    // Drain any remaining channel messages after join_set is empty
    while let Ok(batch) = finding_rx.try_recv() { findings.extend(batch); }
    while let Ok(batch) = error_rx.try_recv()   { errors.extend(batch);   }

    // ── 6. Post-process ───────────────────────────────────────────────────────
    dedup_findings(&mut findings);
    sort_findings(&mut findings);

    let elapsed = start.elapsed();
    info!(
        findings = findings.len(),
        errors   = errors.len(),
        scanned,
        skipped,
        elapsed_ms = elapsed.as_millis(),
        "Run complete"
    );

    RunResult { findings, errors, elapsed, scanned, skipped }
}

// ── Per-URL scan ───────────────────────────────────────────────────────────────

/// Run every enabled scanner against a single URL, sending results on the
/// channels.  Never panics — all errors are captured and forwarded.
async fn scan_url(
    url:      String,
    client:   &HttpClient,
    scanners: &[Arc<dyn Scanner>],
    config:   &Config,
    ftx:      mpsc::UnboundedSender<Vec<Finding>>,
    etx:      mpsc::UnboundedSender<Vec<CapturedError>>,
) {
    debug!(url = %url, scanners = scanners.len(), "Scanning URL");

    // Run all scanners for this URL concurrently (they share the HttpClient
    // which already enforces per-host rate-limiting and concurrency).
    let mut scanner_set: JoinSet<(Vec<Finding>, Vec<CapturedError>)> =
        JoinSet::new();

    for scanner in scanners {
        let s      = Arc::clone(scanner);
        let u      = url.clone();
        let client = client.clone(); // HttpClient is Arc-wrapped internally
        let cfg    = config.clone(); // Config is cheap to clone (all Arcs)

        scanner_set.spawn(async move {
            s.scan(&u, &client, &cfg).await
        });
    }

    while let Some(result) = scanner_set.join_next().await {
        match result {
            Ok((mut f, mut e)) => {
                // Attach the originating URL to every finding (scanner may
                // not know the canonical form we use)
                for finding in &mut f {
                    if finding.url.is_empty() {
                        finding.url = url.clone();
                    }
                }
                if !f.is_empty() { let _ = ftx.send(f); }
                if !e.is_empty() { let _ = etx.send(e); }
            }
            Err(join_err) => {
                // A scanner task panicked — capture as an error
                let ce = CapturedError::internal(
                    format!("Scanner panic on {url}: {join_err}")
                );
                let _ = etx.send(vec![ce]);
            }
        }
    }
}

// ── Scanner registry ───────────────────────────────────────────────────────────

/// Instantiate every scanner that is enabled in `config`.
/// Returns a `Vec<Arc<dyn Scanner>>` so it can be cheaply cloned per worker.
fn build_scanners(config: &Config) -> Vec<Arc<dyn Scanner>> {
    let mut scanners: Vec<Arc<dyn Scanner>> = Vec::new();

    // Each arm is gated on the corresponding config toggle.
    // Add new scanners here — nowhere else needs changing.
    if config.scanners.cors {
        scanners.push(Arc::new(CorsScanner::new(config)));
    }
    if config.scanners.csp {
        scanners.push(Arc::new(CspScanner::new(config)));
    }
    if config.scanners.graphql {
        scanners.push(Arc::new(GraphqlScanner::new(config)));
    }
    if config.scanners.api_security {
        scanners.push(Arc::new(ApiSecurityScanner::new(config)));
    }

    if scanners.is_empty() {
        warn!("All scanners are disabled — no findings will be produced");
    } else {
        info!(
            enabled = scanners.len(),
            "Scanners loaded"
        );
    }

    scanners
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Normalise URLs to their canonical form and remove exact duplicates.
/// Returns `(unique_urls, n_duplicates_dropped)`.
fn dedup(raw: Vec<String>) -> (Vec<String>, usize) {
    let mut seen    = HashSet::with_capacity(raw.len());
    let mut unique  = Vec::with_capacity(raw.len());
    let mut dropped = 0usize;

    for raw_url in raw {
        let canonical = canonicalise(&raw_url).unwrap_or_else(|| raw_url.clone());

        if seen.insert(canonical.clone()) {
            unique.push(canonical);
        } else {
            dropped += 1;
            debug!(url = %raw_url, "Duplicate URL dropped");
        }
    }

    (unique, dropped)
}

/// Best-effort URL canonicalisation:
///   - Lowercase scheme + host
///   - Remove default ports (80 for http, 443 for https)
///   - Remove trailing slash from path (unless path is just "/")
///   - Strip fragment (never meaningful for scanning)
fn canonicalise(raw: &str) -> Option<String> {
    let mut u = Url::parse(raw).ok()?;

    // Lowercase scheme + host (Url::parse lowercases scheme already)
    let host = u.host_str()?.to_ascii_lowercase();
    u.set_host(Some(&host)).ok()?;

    // Strip default ports
    let default_port = match u.scheme() {
        "https" => Some(443),
        "http"  => Some(80),
        _       => None,
    };
    if u.port() == default_port {
        u.set_port(None).ok()?;
    }

    // Strip fragment
    u.set_fragment(None);

    // Remove trailing slash on non-root paths
    let path = u.path().to_owned();
    if path.len() > 1 && path.ends_with('/') {
        u.set_path(path.trim_end_matches('/'));
    }

    Some(u.to_string())
}

/// Hard-cap the work list to `max` items.
/// Returns `(capped_list, n_dropped)`.
fn apply_cap(mut urls: Vec<String>, max: usize) -> (Vec<String>, usize) {
    if max == 0 || urls.len() <= max {
        return (urls, 0);
    }
    let dropped = urls.len() - max;
    urls.truncate(max);
    (urls, dropped)
}

/// Remove duplicate findings based on `(url, check)` key.
/// Keeps the first occurrence (highest-priority / earliest found).
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.url.clone(), f.check.clone())));
}

/// Sort findings: severity descending, then URL, then check slug.
fn sort_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())   // high severity first
            .then_with(|| a.url.cmp(&b.url))
            .then_with(|| a.check.cmp(&b.check))
    });
}
