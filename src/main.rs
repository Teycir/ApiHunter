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

use std::{io, process, sync::Arc, time::Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use chrono::Utc;

use api_scanner::{
    cli::{default_user_agents, load_urls, Cli},
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::{self, ReportConfig, Reporter, ReportFormat, ReportMeta, Severity},
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

    // ── 1. Load URLs ─────────────────────────────────────────────────────────
    let raw_urls = load_urls(&cli)?;
    if raw_urls.is_empty() {
        warn!("No URLs provided — nothing to scan.");
        return Ok(0);
    }
    info!("Loaded {} URL(s) for scanning.", raw_urls.len());

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
            delay_ms:     cli.delay_ms,
            retries:      cli.retries,
            timeout_secs: cli.timeout_secs,
        },
        waf_evasion: WafEvasionConfig {
            enabled:     cli.waf_evasion || !cli.user_agents.is_empty(),
            user_agents: if cli.user_agents.is_empty() {
                default_user_agents()
            } else {
                cli.user_agents.clone()
            },
        },
        default_headers: build_default_headers(&cli.headers, &cli.auth_bearer, &cli.auth_basic)?,
        cookies:         parse_cookies(&cli.cookies)?,
        proxy:                       cli.proxy.clone(),
        danger_accept_invalid_certs: cli.danger_accept_invalid_certs,
        active_checks:              cli.active_checks,
        stream_findings:            cli.stream,
        baseline_path:              cli.baseline.clone(),
        session_file:               cli.session_file.clone(),
        auth_bearer:                cli.auth_bearer.clone(),
        auth_basic:                 cli.auth_basic.clone(),
        per_host_clients:           cli.per_host_clients,
        adaptive_concurrency:       cli.adaptive_concurrency,
        toggles: ScannerToggles {
            cors:         !cli.no_cors,
            csp:          !cli.no_csp,
            graphql:      !cli.no_graphql,
            api_security: !cli.no_api_security,
            jwt:          !cli.no_jwt,
            openapi:      !cli.no_openapi,
        },
    });

    // ── 3. Build shared HttpClient ───────────────────────────────────────────
    let http_client = Arc::new(
        HttpClient::new(&config).context("Failed to build HTTP client")?,
    );

    // ── 4. Build Reporter ─────────────────────────────────────────────────────
    let print_summary = cli.summary || !cli.quiet;
    let mut report_cfg = ReportConfig {
        format:        cli.format.into(),
        output_path:   cli.output.clone(),
        print_summary,
        quiet:         cli.quiet,
        stream:        cli.stream,
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
        });
    }

    // ── 5. Run scanner ────────────────────────────────────────────────────────
    info!("Starting scan with concurrency={}.", config.concurrency);
    let run_result = runner::run(
        raw_urls,
        config.clone(),
        Arc::clone(&http_client),
        reporter.clone(),
    )
    .await;

    // ── 6. Filter findings by --min-severity ─────────────────────────────────
    let min_sev: Severity = cli.min_severity.into();
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
        filtered_result.findings = reports::filter_new_findings(
            filtered_result.findings,
            &baseline,
        );
    }

    // ── 7. Emit report ────────────────────────────────────────────────────────
    reporter.write_run_result(&filtered_result);
    reporter.finalize();

    if config.session_file.is_some() {
        if let Err(e) = http_client.save_session().await {
            warn!("Failed to save session file: {e}");
        }
    }

    let elapsed = start.elapsed();
    info!("Scan finished in {:.2}s.", elapsed.as_secs_f64());

    // ── 8. Compute and return exit code ───────────────────────────────────────
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
    // RUST_LOG always wins; otherwise default to `warn` in quiet mode, `info` otherwise.
    let default_level = if quiet { "warn" } else { "info" };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_writer(io::stderr)   // keep stdout clean for piped JSON output
        .with_target(false)
        .compact()
        .init();
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

    let has_auth = out.iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization"));

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

fn parse_cookies(raws: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for raw in raws {
        let mut parts = raw.splitn(2, '=');
        let name = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if name.is_empty() || value.is_empty() {
            bail!("Invalid cookie format: '{raw}' (expected NAME=VALUE)");
        }
        out.push((name.to_string(), value.to_string()));
    }
    Ok(out)
}
