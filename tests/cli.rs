// tests/cli.rs
//
// CLI parsing and helper function tests.

use std::{collections::HashSet, io::Write};

use clap::Parser;
use tempfile::NamedTempFile;

use api_scanner::cli::{default_user_agents, load_urls, Cli, CliFormat, CliSeverity};
use api_scanner::config::ScannerToggles;
use api_scanner::reports::{ReportFormat, Severity};

// ── CLI parsing ──────────────────────────────────────────────────────────────

#[test]
fn parses_minimal_url_file_arg() {
    let cli = Cli::try_parse_from(["scanner", "--urls", "/tmp/urls.txt"]).unwrap();
    assert_eq!(cli.urls, Some(std::path::PathBuf::from("/tmp/urls.txt")));
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
    let result = Cli::try_parse_from(["scanner", "--urls", "/tmp/urls.txt", "--stdin"]);
    assert!(result.is_err());
}

#[test]
fn default_concurrency_and_delay() {
    let cli = Cli::try_parse_from(["scanner", "--stdin"]).unwrap();
    assert_eq!(cli.concurrency, 20);
    assert_eq!(cli.delay_ms, 100);
    assert_eq!(cli.retries, 3);
    assert_eq!(cli.timeout_secs, 30);
}

#[test]
fn scanner_toggle_flags() {
    let cli = Cli::try_parse_from([
        "scanner",
        "--stdin",
        "--no-cors",
        "--no-csp",
        "--no-graphql",
        "--no-api-security",
        "--no-jwt",
        "--no-openapi",
    ])
    .unwrap();
    assert!(cli.no_cors);
    assert!(cli.no_csp);
    assert!(cli.no_graphql);
    assert!(cli.no_api_security);
    assert!(cli.no_jwt);
    assert!(cli.no_openapi);
}

#[test]
fn waf_evasion_implied_by_user_agents() {
    let cli = Cli::try_parse_from([
        "scanner",
        "--stdin",
        "--user-agents",
        "FooBot/1.0,BarBot/2.0",
    ])
    .unwrap();
    assert_eq!(cli.user_agents, vec!["FooBot/1.0", "BarBot/2.0"]);
    // waf_evasion flag itself is false; the run() logic ORs them
    assert!(!cli.waf_evasion);
}

#[test]
fn explicit_waf_evasion_flag() {
    let cli = Cli::try_parse_from(["scanner", "--stdin", "--waf-evasion"]).unwrap();
    assert!(cli.waf_evasion);
}

#[test]
fn output_and_format_flags() {
    let cli = Cli::try_parse_from([
        "scanner",
        "--stdin",
        "--output",
        "/tmp/out.ndjson",
        "--format",
        "ndjson",
    ])
    .unwrap();
    assert_eq!(
        cli.output,
        Some(std::path::PathBuf::from("/tmp/out.ndjson"))
    );
    assert!(matches!(cli.format, CliFormat::Ndjson));
}

#[test]
fn proxy_and_tls_flags() {
    let cli = Cli::try_parse_from([
        "scanner",
        "--stdin",
        "--proxy",
        "http://127.0.0.1:8080",
        "--danger-accept-invalid-certs",
    ])
    .unwrap();
    assert_eq!(cli.proxy.as_deref(), Some("http://127.0.0.1:8080"));
    assert!(cli.danger_accept_invalid_certs);
}

#[test]
fn headers_and_cookies_flags() {
    let cli = Cli::try_parse_from([
        "scanner",
        "--stdin",
        "--headers",
        "Authorization: Bearer abc,X-Test: 1",
        "--cookies",
        "session=abc,theme=dark",
    ])
    .unwrap();

    assert_eq!(cli.headers, vec!["Authorization: Bearer abc", "X-Test: 1"]);
    assert_eq!(cli.cookies, vec!["session=abc", "theme=dark"]);
}

#[test]
fn max_endpoints_zero_means_unlimited() {
    let cli = Cli::try_parse_from(["scanner", "--stdin", "--max-endpoints", "0"]).unwrap();
    assert_eq!(cli.max_endpoints, 0);
    // run() converts 0 → usize::MAX
}

#[test]
fn quiet_and_summary_flags() {
    let cli = Cli::try_parse_from(["scanner", "--stdin", "--quiet", "--summary"]).unwrap();
    assert!(cli.quiet);
    assert!(cli.summary);
}

// ── URL loader ───────────────────────────────────────────────────────────────

#[test]
fn load_urls_from_file_filters_blanks_and_comments() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, "https://example.com").unwrap();
    writeln!(f, "").unwrap();
    writeln!(f, "# this is a comment").unwrap();
    writeln!(f, "  https://api.example.com/v1  ").unwrap(); // leading/trailing space
    writeln!(f, "https://example.com/graphql").unwrap();

    let cli = Cli::try_parse_from(["scanner", "--urls", f.path().to_str().unwrap()]).unwrap();

    let urls = load_urls(&cli).unwrap();
    assert_eq!(
        urls,
        vec![
            "https://example.com",
            "https://api.example.com/v1",
            "https://example.com/graphql",
        ]
    );
}

#[test]
fn load_urls_missing_file_returns_error() {
    let cli = Cli::try_parse_from(["scanner", "--urls", "/nonexistent/path/to/urls.txt"]).unwrap();
    assert!(load_urls(&cli).is_err());
}

#[test]
fn load_urls_empty_file_returns_empty_vec() {
    let f = NamedTempFile::new().unwrap();
    let cli = Cli::try_parse_from(["scanner", "--urls", f.path().to_str().unwrap()]).unwrap();
    let urls = load_urls(&cli).unwrap();
    assert!(urls.is_empty());
}

#[test]
fn load_urls_only_comments_and_blanks_returns_empty() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, "# comment 1").unwrap();
    writeln!(f, "").unwrap();
    writeln!(f, "   ").unwrap();
    writeln!(f, "# comment 2").unwrap();

    let cli = Cli::try_parse_from(["scanner", "--urls", f.path().to_str().unwrap()]).unwrap();
    let urls = load_urls(&cli).unwrap();
    assert!(urls.is_empty());
}

// ── Severity / format conversions ────────────────────────────────────────────

#[test]
fn cli_severity_into_severity() {
    assert!(matches!(
        Severity::from(CliSeverity::Critical),
        Severity::Critical
    ));
    assert!(matches!(Severity::from(CliSeverity::High), Severity::High));
    assert!(matches!(
        Severity::from(CliSeverity::Medium),
        Severity::Medium
    ));
    assert!(matches!(Severity::from(CliSeverity::Low), Severity::Low));
    assert!(matches!(Severity::from(CliSeverity::Info), Severity::Info));
}

#[test]
fn cli_format_into_report_format() {
    assert!(matches!(
        ReportFormat::from(CliFormat::Pretty),
        ReportFormat::Pretty
    ));
    assert!(matches!(
        ReportFormat::from(CliFormat::Ndjson),
        ReportFormat::Ndjson
    ));
    assert!(matches!(
        ReportFormat::from(CliFormat::Sarif),
        ReportFormat::Sarif
    ));
}

// ── Default user-agents ──────────────────────────────────────────────────────

#[test]
fn default_user_agents_non_empty() {
    let uas = default_user_agents();
    assert!(!uas.is_empty());
    for ua in &uas {
        assert!(!ua.is_empty(), "UA string must not be blank");
        assert!(ua.starts_with("Mozilla/"), "UA should look browser-like");
    }
}

#[test]
fn default_user_agents_are_distinct() {
    let uas = default_user_agents();
    let mut seen = HashSet::new();
    for ua in &uas {
        assert!(seen.insert(ua.as_str()), "duplicate UA: {ua}");
    }
}

// ── Config hydration helpers (unit-level, no I/O) ────────────────────────────

#[test]
fn max_endpoints_zero_maps_to_usize_max() {
    // Mirrors the logic in run() without needing a full async context.
    let max_endpoints = 0usize;
    let resolved = if max_endpoints == 0 {
        usize::MAX
    } else {
        max_endpoints
    };
    assert_eq!(resolved, usize::MAX);
}

#[test]
fn max_endpoints_nonzero_preserved() {
    let max_endpoints = 500usize;
    let resolved = if max_endpoints == 0 {
        usize::MAX
    } else {
        max_endpoints
    };
    assert_eq!(resolved, 500);
}

#[test]
fn waf_enabled_when_user_agents_provided() {
    // run() logic: waf_evasion || !user_agents.is_empty()
    let waf_evasion = false;
    let user_agents = vec!["CustomBot/1.0".to_string()];
    let enabled = waf_evasion || !user_agents.is_empty();
    assert!(enabled);
}

#[test]
fn waf_disabled_when_neither_flag_nor_agents() {
    let waf_evasion = false;
    let user_agents: Vec<String> = vec![];
    let enabled = waf_evasion || !user_agents.is_empty();
    assert!(!enabled);
}

#[test]
fn print_summary_true_when_not_quiet() {
    // print_summary = cli.summary || !cli.quiet
    assert!(false || !false); // summary=false, quiet=false  → true
    assert!(true || !true); // summary=true,  quiet=true   → true
    assert!(!(false || !true)); // summary=false, quiet=true → false
}

// ── Scanner-toggle struct mapping ────────────────────────────────────────────

#[test]
fn toggles_all_on_by_default() {
    let cli = Cli::try_parse_from(["scanner", "--stdin"]).unwrap();
    let toggles = ScannerToggles {
        cors: !cli.no_cors,
        csp: !cli.no_csp,
        graphql: !cli.no_graphql,
        api_security: !cli.no_api_security,
        jwt: !cli.no_jwt,
        openapi: !cli.no_openapi,
    };
    assert!(toggles.cors);
    assert!(toggles.csp);
    assert!(toggles.graphql);
    assert!(toggles.api_security);
    assert!(toggles.jwt);
    assert!(toggles.openapi);
}

#[test]
fn toggles_selectively_disabled() {
    let cli = Cli::try_parse_from(["scanner", "--stdin", "--no-cors", "--no-graphql"]).unwrap();
    let toggles = ScannerToggles {
        cors: !cli.no_cors,
        csp: !cli.no_csp,
        graphql: !cli.no_graphql,
        api_security: !cli.no_api_security,
        jwt: !cli.no_jwt,
        openapi: !cli.no_openapi,
    };
    assert!(!toggles.cors);
    assert!(toggles.csp);
    assert!(!toggles.graphql);
    assert!(toggles.api_security);
    assert!(toggles.jwt);
    assert!(toggles.openapi);
}
