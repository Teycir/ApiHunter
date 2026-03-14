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

use std::{
    fs,
    io::{self, BufRead},
    path::PathBuf,
    process,
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser, ValueEnum};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use crate::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    report::{ReportConfig, ReportFormat, Reporter, Severity},
    runner,
};

// ── CLI definition ────────────────────────────────────────────────────────────

/// A fast, async web security scanner.
///
/// Reads a list of URLs from a file or stdin, runs the enabled checks
/// concurrently, and writes findings in JSON or NDJSON format.
#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about,
    long_about = None,
    // Require exactly one of --urls or --stdin
    group(
        ArgGroup::new("input")
            .required(true)
            .args(["urls", "stdin"])
    )
)]
struct Cli {
    // ── Input ────────────────────────────────────────────────────────────────

    /// Path to a newline-delimited file of URLs to scan.
    #[arg(short = 'u', long, value_name = "FILE", group = "input")]
    urls: Option<PathBuf>,

    /// Read newline-delimited URLs from stdin instead of a file.
    #[arg(long, group = "input")]
    stdin: bool,

    // ── Output ───────────────────────────────────────────────────────────────

    /// Write findings to this file path (default: stdout).
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output format.
    #[arg(short = 'f', long, default_value = "pretty", value_name = "FORMAT")]
    format: CliFormat,

    /// Suppress all stdout output except findings (no summary box).
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Print the summary box even in quiet mode.
    #[arg(long)]
    summary: bool,

    // ── Concurrency & limits ─────────────────────────────────────────────────

    /// Maximum number of concurrent in-flight requests.
    #[arg(short = 'c', long, default_value_t = 20, value_name = "N")]
    concurrency: usize,

    /// Maximum number of endpoints to scan (0 = unlimited).
    #[arg(short = 'n', long, default_value_t = 0, value_name = "N")]
    max_endpoints: usize,

    // ── Politeness ───────────────────────────────────────────────────────────

    /// Per-domain minimum delay between requests (milliseconds).
    #[arg(long, default_value_t = 100, value_name = "MS")]
    delay_ms: u64,

    /// Maximum number of retry attempts on transient errors.
    #[arg(long, default_value_t = 3, value_name = "N")]
    retries: u32,

    /// Per-request timeout (seconds).
    #[arg(long, default_value_t = 30, value_name = "SECS")]
    timeout_secs: u64,

    // ── WAF evasion ──────────────────────────────────────────────────────────

    /// Enable WAF-evasion heuristics (randomised UA, header shuffling, jitter).
    #[arg(long)]
    waf_evasion: bool,

    /// Rotate through these User-Agent strings (comma-separated).
    /// Implies --waf-evasion.
    #[arg(long, value_name = "UA,...", value_delimiter = ',')]
    user_agents: Vec<String>,

    // ── Proxy / TLS ──────────────────────────────────────────────────────────

    /// HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080).
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Accept invalid / self-signed TLS certificates (dangerous).
    #[arg(long)]
    danger_accept_invalid_certs: bool,

    // ── Scanner toggles ──────────────────────────────────────────────────────

    /// Disable the CORS scanner.
    #[arg(long)]
    no_cors: bool,

    /// Disable the CSP scanner.
    #[arg(long)]
    no_csp: bool,

    /// Disable the GraphQL scanner.
    #[arg(long)]
    no_graphql: bool,

    /// Disable the API-security scanner.
    #[arg(long)]
    no_api_security: bool,

    // ── Reporting threshold ───────────────────────────────────────────────────

    /// Minimum severity to include in findings output.
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    min_severity: CliSeverity,

    /// Exit with code 1 when findings at or above this severity are found.
    #[arg(long, default_value = "medium", value_name = "LEVEL")]
    fail_on: CliSeverity,
}

// ── Clap value enums ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliFormat {
    Pretty,
    Ndjson,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<CliSeverity> for Severity {
    fn from(c: CliSeverity) -> Self {
        match c {
            CliSeverity::Critical => Severity::Critical,
            CliSeverity::High     => Severity::High,
            CliSeverity::Medium   => Severity::Medium,
            CliSeverity::Low      => Severity::Low,
            CliSeverity::Info     => Severity::Info,
        }
    }
}

impl From<CliFormat> for ReportFormat {
    fn from(c: CliFormat) -> Self {
        match c {
            CliFormat::Pretty => ReportFormat::Pretty,
            CliFormat::Ndjson => ReportFormat::Ndjson,
        }
    }
}

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
        r.findings = report::filter_findings(&r.findings, &min_sev)
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
    let summary = report::ReportSummary::from_findings(&filtered_result.findings);
    let code = report::exit_code(&summary, fail_on);

    if code & 1 != 0 {
        warn!(
            "Findings at or above '{}' threshold detected (exit 1).",
            fail_on
        );
    }

    Ok(code)
}

// ── URL loader ────────────────────────────────────────────────────────────────

/// Read newline-delimited URLs from a file or stdin.
/// Blank lines and lines starting with `#` are ignored.
fn load_urls(cli: &Cli) -> Result<Vec<String>> {
    let lines: Vec<String> = if let Some(ref path) = cli.urls {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Cannot read URL file: {}", path.display()))?;
        content.lines().map(str::to_owned).collect()
    } else {
        // --stdin
        let stdin = io::stdin();
        stdin.lock().lines().collect::<Result<_, _>>()
            .context("Failed to read URLs from stdin")?
    };

    let urls = lines
        .into_iter()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    Ok(urls)
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

// ── Default user-agents ───────────────────────────────────────────────────────

fn default_user_agents() -> Vec<String> {
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
         AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) \
         AppleWebKit/605.1.15 (KHTML, like Gecko) \
         Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) \
         Gecko/20100101 Firefox/125.0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ── CLI parsing ──────────────────────────────────────────────────────────

    #[test]
    fn parses_minimal_url_file_arg() {
        let cli = Cli::try_parse_from(["scanner", "--urls", "/tmp/urls.txt"]).unwrap();
        assert_eq!(cli.urls, Some(PathBuf::from("/tmp/urls.txt")));
        assert!(!cli.stdin);
    }

    #[test]
    fn parses_stdin_flag() {
        let cli = Cli::try_parse_from(["scanner", "--stdin"]).unwrap();
        assert!(cli.stdin);
        assert!(cli.urls.is_none());
    }

    #[test]
    fn rejects_no_input_source() {
        // Must provide --urls or --stdin
        let result = Cli::try_parse_from(["scanner"]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_both_input_sources() {
        let result = Cli
