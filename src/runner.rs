//! Central orchestration layer.
//!
//! Responsibilities:
//!   1. Accept a deduplicated list of seed URLs.
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
    discovery::{
        common_paths::CommonPathDiscovery, headers::HeaderDiscovery, js::JsDiscovery,
        robots::RobotsDiscovery, sitemap::SitemapDiscovery, swagger::SwaggerDiscovery,
    },
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Reporter},
    scanner::{
        api_security::ApiSecurityScanner, cors::CorsScanner, csp::CspScanner,
        graphql::GraphqlScanner, jwt::JwtScanner, openapi::OpenApiScanner, Scanner,
    },
};

// ── Public surface ─────────────────────────────────────────────────────────────

/// Everything produced by a completed run.
#[derive(Debug, Default)]
pub struct RunResult {
    /// Deduplicated, sorted list of findings across all scanners + URLs.
    pub findings: Vec<Finding>,
    /// Every non-fatal error encountered during the run.
    pub errors: Vec<CapturedError>,
    /// Wall-clock time for the full run.
    pub elapsed: Duration,
    /// How many URLs were actually scanned (may be < input list due to cap).
    pub scanned: usize,
    /// How many URLs were skipped (cap or dedup).
    pub skipped: usize,
}

/// Entry point called from `main`.
pub async fn run(
    urls: Vec<String>,
    config: Arc<Config>,
    http_client: Arc<HttpClient>,
    http_client_b: Option<Arc<HttpClient>>,
    reporter: Arc<Reporter>,
) -> RunResult {
    let start = Instant::now();

    // ── 1. Normalise + deduplicate ────────────────────────────────────────────
    let (unique_seeds, skipped_dedup) = dedup(urls);
    info!(
        total = unique_seeds.len() + skipped_dedup,
        unique = unique_seeds.len(),
        skipped = skipped_dedup,
        "URL list normalised"
    );

    // ── 2. Discovery phase ────────────────────────────────────────────────────
    let (discovered, mut discovery_errors) =
        run_discovery(&unique_seeds, &config, &http_client).await;
    info!(discovered = discovered.len(), "Discovery complete");

    let mut merged = unique_seeds;
    merged.extend(discovered);
    let (unique_all, skipped_merged) = dedup(merged);

    // ── 4. Apply max_endpoints cap ────────────────────────────────────────────
    let (work_list, skipped_cap) = apply_cap(unique_all, config.max_endpoints);
    if skipped_cap > 0 {
        warn!(
            cap = config.max_endpoints,
            skipped = skipped_cap,
            "URL list truncated to max_endpoints"
        );
    }

    let scanned = work_list.len();
    let skipped = skipped_dedup + skipped_merged + skipped_cap;

    if scanned == 0 {
        warn!("No URLs to scan — returning empty result");
        return RunResult {
            elapsed: start.elapsed(),
            skipped,
            ..Default::default()
        };
    }

    // ── 5. Shared state ───────────────────────────────────────────────────────
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let scanners = build_scanners(&config, http_client_b.clone());

    // mpsc channels — workers send back results; main task collects
    let (finding_tx, mut finding_rx) = mpsc::unbounded_channel::<Vec<Finding>>();
    let (error_tx, mut error_rx) = mpsc::unbounded_channel::<Vec<CapturedError>>();

    // ── 6. Spawn worker tasks ─────────────────────────────────────────────────
    let mut join_set: JoinSet<()> = JoinSet::new();

    for url in work_list {
        let sem = Arc::clone(&semaphore);
        let client = Arc::clone(&http_client);
        let scanners = scanners.clone();
        let ftx = finding_tx.clone();
        let etx = error_tx.clone();
        let cfg = Arc::clone(&config);
        let rpt = Arc::clone(&reporter);

        join_set.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(e) => {
                    error!(url = %url, "Semaphore closed: {e}");
                    return;
                }
            };

            scan_url(url, &client, &scanners, &cfg, &rpt, ftx, etx).await;
        });
    }

    // Drop the sender halves we kept in main; workers hold their own clones.
    drop(finding_tx);
    drop(error_tx);

    // ── 7. Collect results while workers run ──────────────────────────────────
    let mut findings: Vec<Finding> = Vec::new();
    let mut errors: Vec<CapturedError> = Vec::new();
    errors.append(&mut discovery_errors);

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(()) => {}
            Err(e) => error!("Worker task panicked: {e}"),
        }
    }

    // Drain any remaining channel messages after workers exit.
    while let Some(batch) = finding_rx.recv().await {
        findings.extend(batch);
    }
    while let Some(batch) = error_rx.recv().await {
        errors.extend(batch);
    }

    // ── 8. Post-process ───────────────────────────────────────────────────────
    dedup_findings(&mut findings);
    sort_findings(&mut findings);

    let elapsed = start.elapsed();
    info!(
        findings = findings.len(),
        errors = errors.len(),
        scanned,
        skipped,
        elapsed_ms = elapsed.as_millis(),
        "Run complete"
    );

    RunResult {
        findings,
        errors,
        elapsed,
        scanned,
        skipped,
    }
}

// ── Per-URL scan ───────────────────────────────────────────────────────────────

async fn scan_url(
    url: String,
    client: &HttpClient,
    scanners: &[Arc<dyn Scanner>],
    config: &Config,
    reporter: &Reporter,
    ftx: mpsc::UnboundedSender<Vec<Finding>>,
    etx: mpsc::UnboundedSender<Vec<CapturedError>>,
) {
    debug!(url = %url, scanners = scanners.len(), "Scanning URL");

    let mut scanner_set: JoinSet<(Vec<Finding>, Vec<CapturedError>)> = JoinSet::new();

    for scanner in scanners {
        let s = Arc::clone(scanner);
        let u = url.clone();
        let client = client.clone();
        let cfg = config.clone();

        scanner_set.spawn(async move { s.scan(&u, &client, &cfg).await });
    }

    while let Some(result) = scanner_set.join_next().await {
        match result {
            Ok((mut f, e)) => {
                for finding in &mut f {
                    if finding.url.is_empty() {
                        finding.url = url.clone();
                    }
                }
                if reporter.stream_enabled() {
                    for finding in &f {
                        reporter.flush_finding(finding);
                    }
                }
                if !f.is_empty() {
                    let _ = ftx.send(f);
                }
                if !e.is_empty() {
                    let _ = etx.send(e);
                }
            }
            Err(join_err) => {
                let ce = CapturedError::internal(format!("Scanner panic on {url}: {join_err}"));
                let _ = etx.send(vec![ce]);
            }
        }
    }
}

// ── Scanner registry ───────────────────────────────────────────────────────────

fn build_scanners(
    config: &Config,
    http_client_b: Option<Arc<HttpClient>>,
) -> Vec<Arc<dyn Scanner>> {
    let mut scanners: Vec<Arc<dyn Scanner>> = Vec::new();

    if config.toggles.cors {
        scanners.push(Arc::new(CorsScanner::new(config)));
    }
    if config.toggles.csp {
        scanners.push(Arc::new(CspScanner::new(config)));
    }
    if config.toggles.graphql {
        scanners.push(Arc::new(GraphqlScanner::new(config)));
    }
    if config.toggles.api_security {
        scanners.push(Arc::new(ApiSecurityScanner::new(
            config,
            http_client_b.clone(),
        )));
    }
    if config.toggles.jwt {
        scanners.push(Arc::new(JwtScanner::new(config)));
    }
    if config.toggles.openapi {
        scanners.push(Arc::new(OpenApiScanner::new(config)));
    }

    if scanners.is_empty() {
        warn!("All scanners are disabled — no findings will be produced");
    } else {
        info!(enabled = scanners.len(), "Scanners loaded");
    }

    scanners
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn dedup(raw: Vec<String>) -> (Vec<String>, usize) {
    let mut seen = HashSet::with_capacity(raw.len());
    let mut unique = Vec::with_capacity(raw.len());
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

fn canonicalise(raw: &str) -> Option<String> {
    let mut u = Url::parse(raw).ok()?;

    let host = u.host_str()?.to_ascii_lowercase();
    u.set_host(Some(&host)).ok()?;

    let default_port = match u.scheme() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    if u.port() == default_port {
        u.set_port(None).ok()?;
    }

    u.set_fragment(None);

    let path = u.path().to_owned();
    if path.len() > 1 && path.ends_with('/') {
        u.set_path(path.trim_end_matches('/'));
    }

    Some(u.to_string())
}

// ── Discovery orchestration ─────────────────────────────────────────────────

async fn run_discovery(
    seeds: &[String],
    config: &Config,
    client: &HttpClient,
) -> (Vec<String>, Vec<CapturedError>) {
    const MAX_SITEMAPS: usize = 5;
    const MAX_SCRIPTS: usize = 10;

    let mut discovered: HashSet<String> = HashSet::new();
    let mut errors: Vec<CapturedError> = Vec::new();

    for seed in seeds {
        let parsed = match Url::parse(seed) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let host = match parsed.host_str() {
            Some(h) => h.to_string(),
            None => continue,
        };

        let base = {
            let mut b = format!("{}://{}", parsed.scheme(), host);
            if let Some(port) = parsed.port() {
                b.push_str(&format!(":{port}"));
            }
            b
        };

        let (paths, errs) = RobotsDiscovery::new(client, &base, &host).run().await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut discovered);

        let (paths, errs) = SitemapDiscovery::new(client, &base, &host, MAX_SITEMAPS)
            .run()
            .await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut discovered);

        let (paths, errs) = SwaggerDiscovery::new(client, &base, &host).run().await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut discovered);

        let (paths, errs) = JsDiscovery::new(client, seed, &host, MAX_SCRIPTS)
            .run()
            .await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut discovered);

        let (paths, errs) = HeaderDiscovery::new(client, &base, &host).run().await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut discovered);

        let (paths, errs) = CommonPathDiscovery::new(client, &base, config.concurrency, Vec::new())
            .run()
            .await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut discovered);
    }

    let urls = discovered.into_iter().collect();
    (urls, errors)
}

fn insert_paths(base: &str, paths: HashSet<String>, out: &mut HashSet<String>) {
    let base = base.trim_end_matches('/');
    for path in paths {
        let url = format!("{base}{path}");
        out.insert(url);
    }
}

fn apply_cap(mut urls: Vec<String>, max: usize) -> (Vec<String>, usize) {
    if max == 0 || urls.len() <= max {
        return (urls, 0);
    }
    let dropped = urls.len() - max;
    urls.truncate(max);
    (urls, dropped)
}

fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.url.clone(), f.check.clone())));
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.url.cmp(&b.url))
            .then_with(|| a.check.cmp(&b.check))
    });
}
