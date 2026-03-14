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

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use api_scanner::{
    cli::{default_user_agents, load_urls, Cli},
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::{self, ReportConfig, Reporter, Severity},
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
        proxy:                       cli.proxy.clone(),
        danger_accept_invalid_certs: cli.danger_accept_invalid_certs,
        toggles: ScannerToggles {
            cors:         !cli.no_cors,
            csp:          !cli.no_csp,
            graphql:      !cli.no_graphql,
            api_security: !cli.no_api_security,
        },
    });

    // ── 3. Build shared HttpClient ───────────────────────────────────────────
    let http_client = Arc::new(
        HttpClient::new(&config).context("Failed to build HTTP client")?,
    );

    // ── 4. Build Reporter ─────────────────────────────────────────────────────
    let print_summary = cli.summary || !cli.quiet;
    let report_cfg = ReportConfig {
        format:        cli.format.into(),
        output_path:   cli.output.clone(),
        print_summary,
        quiet:         cli.quiet,
    };
    let reporter = Arc::new(Reporter::new(report_cfg).context("Failed to create reporter")?);

    // ── 5. Run scanner ────────────────────────────────────────────────────────
    info!("Starting scan with concurrency={}.", config.concurrency);
    let run_result = runner::run(raw_urls, config.clone(), http_client, reporter.clone()).await;

    // ── 6. Filter findings by --min-severity ─────────────────────────────────
    let min_sev: Severity = cli.min_severity.into();
    let fail_on: Severity = cli.fail_on.into();

    let filtered_result = {
        let mut r = run_result;
        r.findings = reports::filter_findings(&r.findings, &min_sev)
            .into_iter()
            .cloned()
            .collect();
        r
    };

    // ── 7. Emit report ────────────────────────────────────────────────────────
    reporter.write_run_result(&filtered_result);
    reporter.finalize();

    let elapsed = start.elapsed();
    info!("Scan finished in {:.2}s.", elapsed.as_secs_f64());

    // ── 8. Compute and return exit code ───────────────────────────────────────
    // build_summary is private, but exit_code works on the full RunResult;
    // we build a lightweight summary inline.
    let summary = {
        let mut s = reports::ReportSummary::default();
        s.total = filtered_result.findings.len();
        s.errors = filtered_result.errors.len();
        for f in &filtered_result.findings {
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High     => s.high     += 1,
                Severity::Medium   => s.medium   += 1,
                Severity::Low      => s.low      += 1,
                Severity::Info     => s.info     += 1,
            }
        }
        s
    };
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
