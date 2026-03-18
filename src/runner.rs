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
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    sync::{mpsc, Semaphore},
    task::JoinSet,
};
use tracing::{debug, error};
use url::Url;

use crate::{
    config::Config,
    discovery::{
        common_paths::CommonPathDiscovery, headers::HeaderDiscovery, js::JsDiscovery,
        robots::RobotsDiscovery, sitemap::SitemapDiscovery, swagger::SwaggerDiscovery,
    },
    error::CapturedError,
    http_client::HttpClient,
    progress_tracker::{ProgressConfig, ProgressTracker},
    reports::{Finding, Reporter},
    scanner::{
        api_security::ApiSecurityScanner, cors::CorsScanner, csp::CspScanner,
        graphql::GraphqlScanner, jwt::JwtScanner, openapi::OpenApiScanner,
        websocket::WebSocketScanner, Scanner,
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
    _quiet: bool,
) -> RunResult {
    let start = Instant::now();

    // ── 1. Normalise + deduplicate ────────────────────────────────────────────
    let (unique_seeds, skipped_dedup) = dedup(urls);

    // ── 2. Discovery phase with per-site cap ────────────────────────────────
    let (discovered, mut discovery_errors) = if config.no_discovery {
        (Vec::new(), Vec::new())
    } else {
        run_discovery_per_site(&unique_seeds, &config, &http_client).await
    };
    if config.no_discovery {
        eprintln!(
            "Discovery skipped (--no-discovery): {} seed endpoints",
            unique_seeds.len()
        );
    } else {
        eprintln!(
            "Discovery complete: {} total endpoints",
            discovered.len() + unique_seeds.len()
        );
    }

    let mut merged = unique_seeds;
    merged.extend(discovered);
    let (work_list, skipped_merged) = dedup(merged);

    let skipped_cap = 0; // No global cap anymore, handled per-site

    let scanned = work_list.len();
    let skipped = skipped_dedup + skipped_merged + skipped_cap;

    if scanned == 0 {
        return RunResult {
            elapsed: start.elapsed(),
            skipped,
            ..Default::default()
        };
    }

    // ── 5. Shared state ───────────────────────────────────────────────────────
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let scanners = build_scanners(&config, http_client_b.clone());

    // Progress tracking
    let tracker = Arc::new(ProgressTracker::with_config(ProgressConfig {
        total: scanned,
        tty_update_frequency: 1,
        non_tty_update_frequency: 1,
        show_elapsed: false,
        show_eta: false,
        show_rate: false,
        prefix: "".to_string(),
        show_details: false,
    }));

    // mpsc channels — workers send back results; main task collects
    let (finding_tx, mut finding_rx) = mpsc::unbounded_channel::<Vec<Finding>>();
    let (error_tx, mut error_rx) = mpsc::unbounded_channel::<Vec<CapturedError>>();

    // ── 6. Spawn worker tasks ─────────────────────────────────────────────────
    let mut join_set: JoinSet<()> = JoinSet::new();

    eprintln!(
        "Scan started: {} | Targets: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        scanned
    );

    for url in work_list {
        let sem = Arc::clone(&semaphore);
        let client = Arc::clone(&http_client);
        let scanners = scanners.clone();
        let ftx = finding_tx.clone();
        let etx = error_tx.clone();
        let cfg = Arc::clone(&config);
        let rpt = Arc::clone(&reporter);
        let progress_handle = tracker.handle();

        join_set.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(e) => {
                    error!(url = %url, "Semaphore closed: {e}");
                    return;
                }
            };

            let (findings, _errors) = scan_url_with_results(
                url.clone(),
                &client,
                &scanners,
                &cfg,
                &rpt,
                ftx.clone(),
                etx.clone(),
            )
            .await;

            // Build summary message for detailed logging
            let mut msg = url.clone();
            if !findings.is_empty() {
                let critical = findings
                    .iter()
                    .filter(|f| matches!(f.severity, crate::reports::Severity::Critical))
                    .count();
                let high = findings
                    .iter()
                    .filter(|f| matches!(f.severity, crate::reports::Severity::High))
                    .count();
                let medium = findings
                    .iter()
                    .filter(|f| matches!(f.severity, crate::reports::Severity::Medium))
                    .count();

                msg.push_str(&format!(" | 🔍 {} findings", findings.len()));
                if critical > 0 {
                    msg.push_str(&format!(" (🔴 {}C", critical));
                }
                if high > 0 {
                    msg.push_str(&format!(" 🟠 {}H", high));
                }
                if medium > 0 {
                    msg.push_str(&format!(" 🟡 {}M", medium));
                }
                if critical > 0 || high > 0 || medium > 0 {
                    msg.push(')');
                }
            } else {
                msg.push_str(" | ✅ Clean");
            }

            // Progress increment (details suppressed by show_details=false)
            progress_handle.increment(Some(&msg)).await;
        });
    }

    // Drop the sender halves we kept in main; workers hold their own clones.
    drop(finding_tx);
    drop(error_tx);

    // ── 7. Collect results while workers run ──────────────────────────────────
    let mut findings: Vec<Finding> = Vec::new();
    let mut errors: Vec<CapturedError> = Vec::new();
    errors.append(&mut discovery_errors);

    loop {
        tokio::select! {
            Some(result) = join_set.join_next() => {
                match result {
                    Ok(()) => {}
                    Err(e) => error!("Worker task panicked: {e}"),
                }
            }
            Some(batch) = finding_rx.recv() => {
                findings.extend(batch);
            }
            Some(batch) = error_rx.recv() => {
                errors.extend(batch);
            }
            else => break,
        }
    }

    // ── 8. Post-process ───────────────────────────────────────────────────────
    tracker.finish().await;

    dedup_findings(&mut findings);
    sort_findings(&mut findings);

    let elapsed = start.elapsed();
    eprintln!(
        "Scan finished: {} | Findings: {} | Scanned: {} | Elapsed: {:.2}s",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        findings.len(),
        scanned,
        elapsed.as_secs_f64()
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

async fn scan_url_with_results(
    url: String,
    client: &HttpClient,
    scanners: &[Arc<dyn Scanner>],
    config: &Config,
    reporter: &Reporter,
    ftx: mpsc::UnboundedSender<Vec<Finding>>,
    etx: mpsc::UnboundedSender<Vec<CapturedError>>,
) -> (Vec<Finding>, Vec<CapturedError>) {
    debug!(url = %url, scanners = scanners.len(), "Scanning URL");

    let mut scanner_set: JoinSet<(Vec<Finding>, Vec<CapturedError>)> = JoinSet::new();
    let mut all_findings = Vec::new();
    let mut all_errors = Vec::new();

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
                all_findings.extend(f.clone());
                all_errors.extend(e.clone());
                if !f.is_empty() {
                    let _ = ftx.send(f);
                }
                if !e.is_empty() {
                    let _ = etx.send(e);
                }
            }
            Err(join_err) => {
                let ce = CapturedError::internal(format!("Scanner panic on {url}: {join_err}"));
                all_errors.push(ce.clone());
                let _ = etx.send(vec![ce]);
            }
        }
    }

    (all_findings, all_errors)
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
    if config.active_checks {
        scanners.push(Arc::new(WebSocketScanner::new(config)));
    }

    if scanners.is_empty() {
        eprintln!("Warning: All scanners disabled");
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

async fn run_discovery_per_site(
    seeds: &[String],
    config: &Config,
    client: &HttpClient,
) -> (Vec<String>, Vec<CapturedError>) {
    const MAX_SITEMAPS: usize = 5;
    const MAX_SCRIPTS: usize = 10;

    let mut all_discovered: HashSet<String> = HashSet::new();
    let mut all_errors: Vec<CapturedError> = Vec::new();

    let sites = group_seeds_by_site(seeds);

    for (base, (host, site_seeds)) in sites {
        let js_seed = match site_seeds.first() {
            Some(s) => s.as_str(),
            None => continue,
        };

        let mut site_discovered: HashSet<String> = HashSet::new();
        let mut errors: Vec<CapturedError> = Vec::new();

        let (paths, errs) = RobotsDiscovery::new(client, &base, &host).run().await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut site_discovered);

        let (paths, errs) = SitemapDiscovery::new(client, &base, &host, MAX_SITEMAPS)
            .run()
            .await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut site_discovered);

        let (paths, errs) = SwaggerDiscovery::new(client, &base, &host).run().await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut site_discovered);

        let (paths, errs) = JsDiscovery::new(client, js_seed, &host, MAX_SCRIPTS)
            .run()
            .await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut site_discovered);

        let (paths, errs) = HeaderDiscovery::new(client, &base, &host).run().await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut site_discovered);

        let (paths, errs) = CommonPathDiscovery::new(client, &base, config.concurrency, Vec::new())
            .run()
            .await;
        errors.extend(errs);
        insert_paths(&base, paths, &mut site_discovered);

        let max_per_site = if config.max_endpoints == 0 {
            usize::MAX
        } else {
            config.max_endpoints
        };

        let site_urls: Vec<String> = site_discovered.into_iter().collect();
        let capped_count = site_urls.len().min(max_per_site);

        if site_urls.len() > max_per_site {
            debug!(
                site = %host,
                discovered = site_urls.len(),
                capped = capped_count,
                "Site endpoints capped"
            );
        }

        all_discovered.extend(site_urls.into_iter().take(capped_count));
        all_errors.extend(errors);
    }

    let urls = all_discovered.into_iter().collect();
    (urls, all_errors)
}

fn group_seeds_by_site(seeds: &[String]) -> BTreeMap<String, (String, Vec<String>)> {
    let mut sites: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();

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

        sites
            .entry(base)
            .and_modify(|(_, list)| list.push(seed.clone()))
            .or_insert_with(|| (host, vec![seed.clone()]));
    }

    sites
}

fn insert_paths(base: &str, paths: HashSet<String>, out: &mut HashSet<String>) {
    let base = base.trim_end_matches('/');
    for path in paths {
        let url = format!("{base}{path}");
        out.insert(url);
    }
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
