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
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use rand::seq::SliceRandom;
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
    progress_tracker::{ProgressConfig, ProgressTracker},
    reports::{Finding, Reporter},
    scanner::{
        api_security::ApiSecurityScanner, cors::CorsScanner, csp::CspScanner,
        cve_templates::CveTemplateScanner, graphql::GraphqlScanner, jwt::JwtScanner,
        mass_assignment::MassAssignmentScanner, oauth_oidc::OAuthOidcScanner,
        openapi::OpenApiScanner, rate_limit::RateLimitScanner, websocket::WebSocketScanner,
        Scanner,
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
    /// Runtime metrics captured during the run.
    pub metrics: RuntimeMetrics,
}

/// Runtime metrics emitted in report metadata.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeMetrics {
    /// Total HTTP requests sent (includes retry attempts).
    pub http_requests: u64,
    /// Total retry attempts performed by the transport layer.
    pub http_retries: u64,
    /// Finding counts grouped by scanner name.
    pub scanner_findings: BTreeMap<String, usize>,
    /// Error counts grouped by scanner name.
    pub scanner_errors: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Clone)]
struct ScannerRunStats {
    findings: usize,
    errors: usize,
}

type ScannerStatsMap = BTreeMap<String, ScannerRunStats>;

#[derive(Debug, Default, Clone, Copy)]
struct UrlScanSummary {
    findings: usize,
    critical: usize,
    high: usize,
    medium: usize,
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
    info!(
        seeds = unique_seeds.len(),
        discovery_enabled = !config.no_discovery,
        active_checks = config.active_checks,
        "Scan lifecycle: seeds prepared"
    );

    // ── 2. Discovery phase with per-site cap ────────────────────────────────
    let (discovered, mut discovery_errors) = if config.no_discovery {
        (Vec::new(), Vec::new())
    } else {
        run_discovery_per_site(&unique_seeds, &config, &http_client).await
    };
    if config.no_discovery {
        info!(
            seeds = unique_seeds.len(),
            "Discovery skipped (--no-discovery)"
        );
    } else {
        info!(
            discovered = discovered.len() + unique_seeds.len(),
            "Discovery complete"
        );
    }

    let mut merged = unique_seeds;
    merged.extend(discovered);
    let (work_list, skipped_merged) = dedup(merged);

    info!(
        discovered = work_list.len(),
        skipped_dedup, skipped_merged, "Scan lifecycle: discovery merged"
    );

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
    let scanner_names: Vec<&str> = scanners.iter().map(|s| s.name()).collect();
    info!(
        scanner_count = scanners.len(),
        scanners = ?scanner_names,
        concurrency = config.concurrency,
        "Scan lifecycle: scanner registry ready"
    );

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
    let (scanner_stats_tx, mut scanner_stats_rx) = mpsc::unbounded_channel::<ScannerStatsMap>();

    // ── 6. Spawn worker tasks ─────────────────────────────────────────────────
    let mut join_set: JoinSet<()> = JoinSet::new();

    info!(
        started_at = %chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        scanned,
        "Scan started"
    );

    for url in work_list {
        let sem = Arc::clone(&semaphore);
        let client = Arc::clone(&http_client);
        let scanners = scanners.clone();
        let ftx = finding_tx.clone();
        let etx = error_tx.clone();
        let stx = scanner_stats_tx.clone();
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

            let (url_summary, scanner_stats) = scan_url_with_results(
                url.clone(),
                &client,
                &scanners,
                &cfg,
                &rpt,
                ftx.clone(),
                etx.clone(),
            )
            .await;

            if !scanner_stats.is_empty() {
                let _ = stx.send(scanner_stats);
            }

            // Build summary message for detailed logging
            let mut msg = url.clone();
            if url_summary.findings > 0 {
                msg.push_str(&format!(" | 🔍 {} findings", url_summary.findings));
                if url_summary.critical > 0 {
                    msg.push_str(&format!(" (🔴 {}C", url_summary.critical));
                }
                if url_summary.high > 0 {
                    msg.push_str(&format!(" 🟠 {}H", url_summary.high));
                }
                if url_summary.medium > 0 {
                    msg.push_str(&format!(" 🟡 {}M", url_summary.medium));
                }
                if url_summary.critical > 0 || url_summary.high > 0 || url_summary.medium > 0 {
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
    drop(scanner_stats_tx);

    // ── 7. Collect results while workers run ──────────────────────────────────
    let mut findings: Vec<Finding> = Vec::new();
    let mut errors: Vec<CapturedError> = Vec::new();
    let mut scanner_stats: ScannerStatsMap = BTreeMap::new();
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
            Some(batch) = scanner_stats_rx.recv() => {
                merge_scanner_stats(&mut scanner_stats, batch);
            }
            else => break,
        }
    }

    // ── 8. Post-process ───────────────────────────────────────────────────────
    tracker.finish().await;

    findings = crate::reports::dedup_findings(findings);
    sort_findings(&mut findings);
    dedup_errors(&mut errors);

    let elapsed = start.elapsed();
    let primary_http_metrics = http_client.runtime_metrics();
    let secondary_http_metrics = http_client_b
        .as_ref()
        .map(|client| client.runtime_metrics())
        .unwrap_or_default();

    let mut scanner_findings = BTreeMap::new();
    let mut scanner_errors = BTreeMap::new();
    for (name, stats) in scanner_stats {
        scanner_findings.insert(name.clone(), stats.findings);
        scanner_errors.insert(name, stats.errors);
    }

    info!(
        findings = findings.len(),
        errors = errors.len(),
        scanned,
        skipped,
        elapsed_ms = elapsed.as_millis(),
        "Scan lifecycle: completed"
    );

    info!(
        finished_at = %chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        findings = findings.len(),
        scanned,
        elapsed_secs = elapsed.as_secs_f64(),
        "Scan finished"
    );

    RunResult {
        findings,
        errors,
        elapsed,
        scanned,
        skipped,
        metrics: RuntimeMetrics {
            http_requests: primary_http_metrics.requests_sent
                + secondary_http_metrics.requests_sent,
            http_retries: primary_http_metrics.retries_performed
                + secondary_http_metrics.retries_performed,
            scanner_findings,
            scanner_errors,
        },
    }
}

// ── Per-URL scan ───────────────────────────────────────────────────────────────

async fn scan_url_with_results(
    url: String,
    client: &HttpClient,
    scanners: &[RegisteredScanner],
    config: &Config,
    reporter: &Reporter,
    ftx: mpsc::UnboundedSender<Vec<Finding>>,
    etx: mpsc::UnboundedSender<Vec<CapturedError>>,
) -> (UrlScanSummary, ScannerStatsMap) {
    debug!(url = %url, scanners = scanners.len(), "Scanning URL");

    let mut scanner_set: JoinSet<(String, Vec<Finding>, Vec<CapturedError>)> = JoinSet::new();
    let mut summary = UrlScanSummary::default();
    let mut scanner_stats: ScannerStatsMap = BTreeMap::new();

    for scanner in scanners {
        let scanner_name = scanner.name().to_string();
        let s = Arc::clone(&scanner.scanner);
        let u = url.clone();
        let client = client.clone();
        let cfg = config.clone();

        scanner_set.spawn(async move {
            let (findings, errors) = s.scan(&u, &client, &cfg).await;
            (scanner_name, findings, errors)
        });
    }

    while let Some(result) = scanner_set.join_next().await {
        match result {
            Ok((scanner_name, mut f, e)) => {
                let stats = scanner_stats.entry(scanner_name).or_default();
                stats.findings += f.len();
                stats.errors += e.len();

                summary.findings += f.len();
                summary.critical += f
                    .iter()
                    .filter(|x| matches!(x.severity, crate::reports::Severity::Critical))
                    .count();
                summary.high += f
                    .iter()
                    .filter(|x| matches!(x.severity, crate::reports::Severity::High))
                    .count();
                summary.medium += f
                    .iter()
                    .filter(|x| matches!(x.severity, crate::reports::Severity::Medium))
                    .count();

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

    (summary, scanner_stats)
}

// ── Scanner registry ───────────────────────────────────────────────────────────

fn build_scanners(
    config: &Config,
    http_client_b: Option<Arc<HttpClient>>,
) -> Vec<RegisteredScanner> {
    let mut scanners: Vec<RegisteredScanner> = Vec::new();

    if config.toggles.cors {
        scanners.push(RegisteredScanner::new(Arc::new(CorsScanner::new(config))));
    }
    if config.toggles.csp {
        scanners.push(RegisteredScanner::new(Arc::new(CspScanner::new(config))));
    }
    if config.toggles.graphql {
        scanners.push(RegisteredScanner::new(Arc::new(GraphqlScanner::new(
            config,
        ))));
    }
    if config.toggles.api_security {
        scanners.push(RegisteredScanner::new(Arc::new(ApiSecurityScanner::new(
            config,
            http_client_b.clone(),
        ))));
    }
    if config.toggles.jwt {
        scanners.push(RegisteredScanner::new(Arc::new(JwtScanner::new(config))));
    }
    if config.toggles.openapi {
        scanners.push(RegisteredScanner::new(Arc::new(OpenApiScanner::new(
            config,
        ))));
    }
    if config.active_checks {
        if config.toggles.mass_assignment {
            scanners.push(RegisteredScanner::new(Arc::new(
                MassAssignmentScanner::new(config),
            )));
        }
        if config.toggles.oauth_oidc {
            scanners.push(RegisteredScanner::new(Arc::new(OAuthOidcScanner::new(
                config,
            ))));
        }
        if config.toggles.rate_limit {
            scanners.push(RegisteredScanner::new(Arc::new(RateLimitScanner::new(
                config,
            ))));
        }
        if config.toggles.cve_templates {
            scanners.push(RegisteredScanner::new(Arc::new(CveTemplateScanner::new(
                config,
            ))));
        }
        if config.toggles.websocket {
            scanners.push(RegisteredScanner::new(Arc::new(WebSocketScanner::new(
                config,
            ))));
        }
    }

    if scanners.is_empty() {
        warn!("All scanners disabled");
    } else if scanners.len() > 1 && should_shuffle_scanners() {
        // Reduce deterministic scanner ordering fingerprints across runs.
        let mut rng = rand::thread_rng();
        scanners.shuffle(&mut rng);
    }

    scanners
}

#[derive(Clone)]
struct RegisteredScanner {
    scanner: Arc<dyn Scanner>,
}

impl RegisteredScanner {
    fn new(scanner: Arc<dyn Scanner>) -> Self {
        Self { scanner }
    }

    fn name(&self) -> &'static str {
        self.scanner.name()
    }
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

    if let Some(query) = u.query() {
        let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if pairs.is_empty() {
            u.set_query(None);
        } else {
            pairs.sort_unstable();
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in pairs {
                serializer.append_pair(&k, &v);
            }
            let normalised_query = serializer.finish();
            u.set_query(Some(&normalised_query));
        }
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
    let discovery_timeout_secs = config.politeness.timeout_secs.saturating_mul(2).max(1);
    let discovery_timeout = Duration::from_secs(discovery_timeout_secs);

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
        let robots = RobotsDiscovery::new(client, &base, &host);
        let sitemap = SitemapDiscovery::new(client, &base, &host, MAX_SITEMAPS);
        let swagger = SwaggerDiscovery::new(client, &base, &host);
        let js = JsDiscovery::new(client, js_seed, &host, MAX_SCRIPTS);
        let headers = HeaderDiscovery::new(client, &base, &host);
        let common_paths = CommonPathDiscovery::new(client, &base, config.concurrency, Vec::new());

        let robots_fut =
            run_discovery_with_timeout(&base, "robots", discovery_timeout, robots.run());
        let sitemap_fut =
            run_discovery_with_timeout(&base, "sitemap", discovery_timeout, sitemap.run());
        let swagger_fut =
            run_discovery_with_timeout(&base, "swagger", discovery_timeout, swagger.run());
        let js_fut = run_discovery_with_timeout(&base, "js", discovery_timeout, js.run());
        let headers_fut =
            run_discovery_with_timeout(&base, "headers", discovery_timeout, headers.run());
        let common_paths_fut = run_discovery_with_timeout(
            &base,
            "common-paths",
            discovery_timeout,
            common_paths.run(),
        );

        let (
            (robots_paths, robots_errs),
            (sitemap_paths, sitemap_errs),
            (swagger_paths, swagger_errs),
            (js_paths, js_errs),
            (header_paths, header_errs),
            (common_paths, common_errs),
        ) = tokio::join!(
            robots_fut,
            sitemap_fut,
            swagger_fut,
            js_fut,
            headers_fut,
            common_paths_fut
        );

        errors.extend(robots_errs);
        insert_paths(&base, robots_paths, &mut site_discovered);

        errors.extend(sitemap_errs);
        insert_paths(&base, sitemap_paths, &mut site_discovered);

        errors.extend(swagger_errs);
        insert_paths(&base, swagger_paths, &mut site_discovered);

        errors.extend(js_errs);
        insert_paths(&base, js_paths, &mut site_discovered);

        errors.extend(header_errs);
        insert_paths(&base, header_paths, &mut site_discovered);

        errors.extend(common_errs);
        insert_paths(&base, common_paths, &mut site_discovered);

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

async fn run_discovery_with_timeout<F>(
    base: &str,
    step: &'static str,
    timeout: Duration,
    fut: F,
) -> (HashSet<String>, Vec<CapturedError>)
where
    F: Future<Output = (HashSet<String>, Vec<CapturedError>)>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok((paths, errs)) => (paths, errs),
        Err(_) => (
            HashSet::new(),
            vec![CapturedError::from_str(
                format!("discovery/{step}"),
                Some(base.to_string()),
                format!(
                    "Discovery step '{step}' timed out after {}s",
                    timeout.as_secs()
                ),
            )],
        ),
    }
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

fn dedup_errors(errors: &mut Vec<CapturedError>) {
    let mut seen = HashSet::new();
    errors.retain(|error| {
        seen.insert((
            error.context.clone(),
            error.url.clone(),
            error.error_type.clone(),
            error.message.clone(),
        ))
    });
}

fn merge_scanner_stats(target: &mut ScannerStatsMap, batch: ScannerStatsMap) {
    for (name, stats) in batch {
        let entry = target.entry(name).or_default();
        entry.findings += stats.findings;
        entry.errors += stats.errors;
    }
}

fn should_shuffle_scanners() -> bool {
    if cfg!(test) {
        return false;
    }
    // Integration tests run the library as a normal dependency, so cfg(test)
    // is not always set. RUST_TEST_THREADS is present in cargo test binaries.
    if std::env::var_os("RUST_TEST_THREADS").is_some() {
        return false;
    }
    std::env::var_os("APIHUNTER_DETERMINISTIC_SCANNER_ORDER").is_none()
}
