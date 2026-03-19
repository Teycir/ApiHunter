// src/main.rs
//
// CLI entry-point for the web security scanner.
//
// Responsibilities
// ────────────────
// 1. Parse CLI arguments (clap derive).
// 2. Initialise the tracing subscriber (stderr, respects --quiet / RUST_LOG).
// 3. Hydrate Config + ReportConfig from parsed args.
// 4. Load the URL list from file or stdin.
// 5. Build the shared HttpClient.
// 6. Create the Reporter.
// 7. Drive runner::run().
// 8. Hand RunResult to Reporter, print summary, emit exit code.

use std::{collections::HashMap, io, path::Path, process, sync::Arc, time::Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use chrono::Utc;
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use api_scanner::{
    auth, auto_report,
    cli::{default_user_agents, load_urls, Cli},
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::{self, ReportConfig, ReportFormat, ReportMeta, Reporter, Severity},
    runner,
};

// ── Entry-point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Clap parse — exits automatically on --help / --version / bad args.
    let cli = Cli::parse();

    // Tracing: honour RUST_LOG; fall back to `info` unless --quiet.
    init_tracing(cli.quiet);

    match run(cli).await {
        Ok(code) => process::exit(code),
        Err(err) => {
            error!("{err:#}");
            process::exit(2);
        }
    }
}

// ── Core async logic ──────────────────────────────────────────────────────────

async fn run(cli: Cli) -> Result<i32> {
    let start = Instant::now();
    validate_startup_inputs(&cli)?;
    emit_security_hygiene_warnings(&cli);
    let mut auth_refresh_tasks = Vec::new();

    // ── 1. Load URLs ─────────────────────────────────────────────────────────
    let raw_urls = load_urls(&cli)?;
    if raw_urls.is_empty() {
        warn!("No URLs provided — nothing to scan.");
        return Ok(0);
    }

    // ── 2. Build Config ──────────────────────────────────────────────────────
    let max_endpoints = if cli.max_endpoints == 0 {
        usize::MAX
    } else {
        cli.max_endpoints
    };

    let config = Arc::new(Config {
        max_endpoints,
        concurrency: cli.concurrency,
        politeness: PolitenessConfig {
            delay_ms: cli.delay_ms,
            retries: cli.retries,
            timeout_secs: cli.timeout_secs,
        },
        waf_evasion: WafEvasionConfig {
            enabled: cli.waf_evasion || !cli.user_agents.is_empty(),
            user_agents: if cli.user_agents.is_empty() {
                default_user_agents()
            } else {
                cli.user_agents.clone()
            },
        },
        default_headers: build_default_headers(&cli.headers, &cli.auth_bearer, &cli.auth_basic)?,
        cookies: parse_cookies(&cli.cookies)?,
        proxy: cli.proxy.clone(),
        danger_accept_invalid_certs: cli.danger_accept_invalid_certs,
        active_checks: cli.active_checks,
        dry_run: cli.dry_run,
        stream_findings: cli.stream,
        baseline_path: cli.baseline.clone(),
        session_file: cli.session_file.clone(),
        auth_bearer: cli.auth_bearer.clone(),
        auth_basic: cli.auth_basic.clone(),
        auth_flow: cli.auth_flow.clone(),
        auth_flow_b: cli.auth_flow_b.clone(),
        unauth_strip_headers: build_unauth_strip_headers(cli.unauth_strip_headers.as_deref()),
        per_host_clients: cli.per_host_clients,
        adaptive_concurrency: cli.adaptive_concurrency,
        no_discovery: cli.no_discovery,
        quiet: cli.quiet,
        toggles: ScannerToggles {
            cors: !cli.no_cors,
            csp: !cli.no_csp,
            graphql: !cli.no_graphql,
            api_security: !cli.no_api_security,
            jwt: !cli.no_jwt,
            openapi: !cli.no_openapi,
            mass_assignment: !cli.no_mass_assignment,
            oauth_oidc: !cli.no_oauth_oidc,
            rate_limit: !cli.no_rate_limit,
            cve_templates: !cli.no_cve_templates,
            websocket: !cli.no_websocket,
        },
    });

    // ── 1b. Filter inaccessible URLs ─────────────────────────────────────────
    let (filtered_urls, inaccessible_urls) = if !cli.no_filter {
        info!(total = raw_urls.len(), "Filtering URL accessibility");
        let (accessible, inaccessible) =
            filter_accessible_urls(&raw_urls, cli.filter_timeout, config.as_ref()).await;
        info!(
            accessible = accessible.len(),
            inaccessible = inaccessible.len(),
            "URL accessibility filtering complete"
        );
        (accessible, inaccessible)
    } else {
        (raw_urls, Vec::new())
    };

    // Keep inaccessible URL visibility in one canonical place to avoid double logging.
    if !inaccessible_urls.is_empty() {
        info!(
            count = inaccessible_urls.len(),
            "Inaccessible URLs filtered from scan seeds"
        );
        for url in &inaccessible_urls {
            info!(url = %url, "Inaccessible URL");
        }
    }

    if filtered_urls.is_empty() {
        warn!("No accessible URLs remaining after filtering.");
        return Ok(0);
    }

    print_banner(&cli, filtered_urls.len());
    info!("Started discovering endpoints");

    if config.danger_accept_invalid_certs {
        warn!("TLS certificate validation is disabled (--danger-accept-invalid-certs). This is insecure for production scans.");
    }

    // ── 3. Build shared HttpClient ───────────────────────────────────────────
    // Execute auth flow if provided
    let http_client = if let Some(ref flow_path) = config.auth_flow {
        let flow = auth::load_flow(flow_path).context("Failed to load auth flow")?;

        info!("Executing auth flow from {}...", flow_path.display());
        let cred = auth::execute_flow(&flow, config.as_ref())
            .await
            .context("Auth flow failed")?;
        let cred = Arc::new(cred);

        // Spawn background refresh task
        auth_refresh_tasks.push(auth::spawn_refresh_task(
            flow,
            Arc::clone(&cred),
            config.as_ref().clone(),
        ));

        Arc::new(
            HttpClient::new(&config)
                .context("Failed to build HTTP client")?
                .with_credential(cred),
        )
    } else {
        Arc::new(HttpClient::new(&config).context("Failed to build HTTP client")?)
    };

    // Second credential for IDOR cross-user checks
    let http_client_b: Option<Arc<HttpClient>> = if let Some(ref flow_path) = config.auth_flow_b {
        let flow = auth::load_flow(flow_path).context("Failed to load auth flow B")?;
        let cred = auth::execute_flow(&flow, config.as_ref())
            .await
            .context("Auth flow B failed")?;
        let cred = Arc::new(cred);
        auth_refresh_tasks.push(auth::spawn_refresh_task(
            flow,
            Arc::clone(&cred),
            config.as_ref().clone(),
        ));
        Some(Arc::new(
            HttpClient::new(&config)
                .context("Failed to build HTTP client B")?
                .with_credential(cred),
        ))
    } else {
        None
    };

    // ── 4. Build Reporter ─────────────────────────────────────────────────────
    let print_summary = cli.summary || !cli.quiet;

    let mut report_cfg = ReportConfig {
        format: cli.format.into(),
        output_path: cli.output.clone(),
        print_summary,
        quiet: cli.quiet,
        stream: cli.stream,
    };
    if report_cfg.stream && report_cfg.format != ReportFormat::Ndjson {
        warn!("--stream is only supported for NDJSON output; disabling streaming.");
        report_cfg.stream = false;
    }
    if report_cfg.stream && cli.baseline.is_some() {
        warn!("--baseline is not compatible with --stream; disabling streaming.");
        report_cfg.stream = false;
    }
    let reporter = Arc::new(Reporter::new(report_cfg).context("Failed to create reporter")?);

    if reporter.stream_enabled() {
        reporter.start_stream(&ReportMeta {
            generated_at: Utc::now(),
            elapsed_ms: 0,
            scanned: 0,
            skipped: 0,
            scanner_ver: env!("CARGO_PKG_VERSION"),
            runtime_metrics: runner::RuntimeMetrics::default(),
        });
    }

    // ── 5. Run scanner ────────────────────────────────────────────────────────
    let run_result = runner::run(
        filtered_urls,
        config.clone(),
        Arc::clone(&http_client),
        http_client_b,
        reporter.clone(),
        cli.quiet,
    )
    .await;

    // ── 6. Filter findings by --min-severity ─────────────────────────────────
    let min_sev: Severity = match cli.min_severity {
        Some(s) => s.into(),
        None => Severity::Info,
    };
    let fail_on: Severity = cli.fail_on.into();

    let mut filtered_result = {
        let mut r = run_result;
        r.findings = reports::filter_findings(&r.findings, &min_sev)
            .into_iter()
            .cloned()
            .collect();
        r
    };

    if let Some(path) = &cli.baseline {
        let baseline = reports::load_baseline_keys(path)?;
        filtered_result.findings =
            reports::filter_new_findings(filtered_result.findings, &baseline);
    }

    // ── 7. Emit report ────────────────────────────────────────────────────────
    reporter.write_run_result(&filtered_result);
    reporter.finalize();

    // ── 8. Auto-save report ───────────────────────────────────────────────────
    let doc = reports::build_document(&filtered_result);
    let min_sev_str = match cli.min_severity {
        Some(s) => format!("{:?}", s),
        None => "Info".to_string(),
    };
    if !cli.no_auto_report {
        if let Err(e) = auto_report::save_auto_report(&filtered_result, &doc, &min_sev_str) {
            warn!("Failed to auto-save report: {e}");
        }
    }

    if config.session_file.is_some() {
        if let Err(e) = http_client.save_session().await {
            warn!("Failed to save session file: {e}");
        }
    }

    for task in auth_refresh_tasks {
        task.shutdown().await;
    }

    let elapsed = start.elapsed();
    info!(elapsed_ms = elapsed.as_millis(), "Run lifecycle: completed");

    // ── 9. Compute and return exit code ───────────────────────────────────────
    let summary = reports::build_summary(&filtered_result);
    let code = reports::exit_code(&summary, &fail_on);

    if code & 1 != 0 {
        warn!(
            "Findings at or above '{}' threshold detected (exit 1).",
            fail_on
        );
    }

    Ok(code)
}

// ── Tracing initialisation ────────────────────────────────────────────────────

fn init_tracing(quiet: bool) {
    let default_level = if quiet { "error" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_target(false)
        .with_ansi(false)
        .compact()
        .init();
}

fn print_banner(_cli: &Cli, url_count: usize) {
    let version = env!("CARGO_PKG_VERSION");
    eprintln!("ApiHunter v{} | Targets: {}", version, url_count);
}

fn build_default_headers(
    raws: &[String],
    auth_bearer: &Option<String>,
    auth_basic: &Option<String>,
) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for raw in raws {
        let mut parts = raw.splitn(2, ':');
        let name = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if name.is_empty() || value.is_empty() {
            bail!("Invalid header format: '{raw}' (expected NAME:VALUE)");
        }
        out.push((name.to_string(), value.to_string()));
    }

    let has_auth = out
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("authorization"));

    if !has_auth {
        if let Some(token) = auth_bearer {
            out.push(("Authorization".to_string(), format!("Bearer {token}")));
        } else if let Some(creds) = auth_basic {
            let encoded = BASE64_STD.encode(creds.as_bytes());
            out.push(("Authorization".to_string(), format!("Basic {encoded}")));
        }
    }
    Ok(out)
}

fn validate_startup_inputs(cli: &Cli) -> Result<()> {
    if cli.timeout_secs == 0 {
        bail!("--timeout-secs must be greater than 0");
    }
    if !cli.no_filter && cli.filter_timeout == 0 {
        bail!("--filter-timeout must be greater than 0 when URL filtering is enabled");
    }
    if cli.concurrency == 0 {
        bail!("--concurrency must be greater than 0");
    }

    if let Some(token) = &cli.auth_bearer {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            bail!("--auth-bearer cannot be empty");
        }
        if trimmed != token || token.chars().any(char::is_whitespace) {
            bail!("--auth-bearer must not contain whitespace");
        }
    }

    if let Some(creds) = &cli.auth_basic {
        let Some((user, pass)) = creds.split_once(':') else {
            bail!("--auth-basic must use USER:PASS format");
        };
        if user.is_empty() || pass.is_empty() {
            bail!("--auth-basic must include non-empty USER and PASS");
        }
    }

    if let Some(path) = &cli.auth_flow {
        validate_auth_flow_path("--auth-flow", path)?;
    }
    if let Some(path) = &cli.auth_flow_b {
        validate_auth_flow_path("--auth-flow-b", path)?;
    }

    Ok(())
}

fn validate_auth_flow_path(flag: &str, path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("{flag} file not found: {}", path.display());
    }
    if !path.is_file() {
        bail!("{flag} must point to a file: {}", path.display());
    }
    std::fs::File::open(path)
        .with_context(|| format!("{flag} file is not readable: {}", path.display()))?;
    Ok(())
}

fn emit_security_hygiene_warnings(cli: &Cli) {
    if cli.concurrency > 500 {
        warn!(
            "--concurrency={} is very high and may overload your scanner host or target systems.",
            cli.concurrency
        );
    }

    if cli.retries > 5 {
        warn!(
            "--retries={} may significantly increase request volume on unstable targets.",
            cli.retries
        );
    }

    for raw in &cli.headers {
        let mut parts = raw.splitn(2, ':');
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }

        if looks_sensitive_header_name(&name) {
            warn!(
                "Sensitive header '{}' provided on CLI; shell history may expose plaintext secrets.",
                name
            );
        }
    }

    for raw in &cli.cookies {
        let mut parts = raw.splitn(2, '=');
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }
        if looks_sensitive_cookie_name(&name) {
            warn!(
                "Sensitive cookie '{}' provided on CLI; shell history may expose plaintext secrets.",
                name
            );
        }
    }
}

fn looks_sensitive_header_name(name: &str) -> bool {
    const KEYS: &[&str] = &[
        "authorization",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "cookie",
        "token",
        "secret",
    ];
    KEYS.iter().any(|k| name.contains(k))
}

fn looks_sensitive_cookie_name(name: &str) -> bool {
    const KEYS: &[&str] = &["session", "token", "auth", "jwt", "secret"];
    KEYS.iter().any(|k| name.contains(k))
}

fn parse_cookies(raws: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for raw in raws {
        let mut parts = raw.splitn(2, '=');
        let name = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if name.is_empty() {
            bail!("Invalid cookie format: '{raw}' (expected NAME=VALUE)");
        }
        out.push((name.to_string(), value.to_string()));
    }
    Ok(out)
}

fn build_unauth_strip_headers(raws: Option<&[String]>) -> Vec<String> {
    raws.unwrap_or(&[])
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ── URL accessibility filter ──────────────────────────────────────────────

async fn filter_accessible_urls(
    urls: &[String],
    timeout_secs: u64,
    config: &Config,
) -> (Vec<String>, Vec<String>) {
    use futures::stream::{self, StreamExt};
    use tokio::sync::Mutex;

    let client = match build_filter_client(config, timeout_secs) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build URL filter client: {e}");
            warn!("Skipping URL accessibility filtering.");
            return (urls.to_vec(), Vec::new());
        }
    };

    let host_last_request: Arc<Mutex<HashMap<String, tokio::time::Instant>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let results: Vec<(String, bool)> = stream::iter(urls)
        .map(|url| {
            let client = client.clone();
            let url = url.clone();
            let host_last_request = Arc::clone(&host_last_request);
            let delay_ms = config.politeness.delay_ms;
            async move {
                enforce_filter_host_delay(host_last_request.as_ref(), &url, delay_ms).await;
                let is_accessible = match client.get(&url).send().await {
                    // Any HTTP response means target is reachable (including 4xx/5xx).
                    Ok(_) => true,
                    // Treat only real network unreachability as inaccessible.
                    Err(e) => !(e.is_connect() || e.is_timeout()),
                };
                (url, is_accessible)
            }
        })
        .buffer_unordered(20)
        .collect()
        .await;

    let mut accessible = Vec::new();
    let mut inaccessible = Vec::new();

    for (url, is_accessible) in results {
        if is_accessible {
            accessible.push(url);
        } else {
            inaccessible.push(url);
        }
    }

    (accessible, inaccessible)
}

fn build_filter_client(
    config: &Config,
    timeout_secs: u64,
) -> Result<reqwest::Client, reqwest::Error> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use tokio::time::Duration;

    let mut default_headers = HeaderMap::new();
    for (k, v) in &config.default_headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            default_headers.insert(name, value);
        }
    }

    if !config.cookies.is_empty() {
        let cookie_value = config
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");

        let key = HeaderName::from_static("cookie");
        if let Some(existing) = default_headers.get(&key).cloned() {
            let mut combined = existing.to_str().unwrap_or("").to_string();
            if !combined.is_empty() {
                combined.push_str("; ");
            }
            combined.push_str(&cookie_value);
            if let Ok(value) = HeaderValue::from_str(&combined) {
                default_headers.insert(key, value);
            }
        } else if let Ok(value) = HeaderValue::from_str(&cookie_value) {
            default_headers.insert(key, value);
        }
    }

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(2))
        .danger_accept_invalid_certs(config.danger_accept_invalid_certs)
        .redirect(reqwest::redirect::Policy::limited(3));

    if !default_headers.is_empty() {
        builder = builder.default_headers(default_headers);
    }

    if let Some(proxy_url) = &config.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy_url)?);
    }

    builder.build()
}

async fn enforce_filter_host_delay(
    host_last_request: &tokio::sync::Mutex<HashMap<String, tokio::time::Instant>>,
    url: &str,
    delay_ms: u64,
) {
    if delay_ms == 0 {
        return;
    }

    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return,
    };

    let host = match parsed.host_str() {
        Some(h) => h,
        None => return,
    };

    let mut key = host.to_string();
    if let Some(port) = parsed.port() {
        key.push_str(&format!(":{port}"));
    }

    let min_gap = tokio::time::Duration::from_millis(delay_ms);
    let now = tokio::time::Instant::now();

    let sleep_for = {
        let mut map = host_last_request.lock().await;
        let next_allowed = match map.get(&key) {
            Some(last) => {
                let candidate = *last + min_gap;
                if candidate > now {
                    candidate
                } else {
                    now
                }
            }
            None => now,
        };
        map.insert(key, next_allowed);
        if next_allowed > now {
            next_allowed - now
        } else {
            tokio::time::Duration::from_millis(0)
        }
    };

    if !sleep_for.is_zero() {
        tokio::time::sleep(sleep_for).await;
    }
}
