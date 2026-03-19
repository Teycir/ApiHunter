use std::net::TcpListener;
use std::sync::Arc;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::rate_limit::RateLimitScanner,
    scanner::Scanner,
};

fn test_config(active_checks: bool) -> Config {
    test_config_with_timeout(active_checks, 5)
}

fn test_config_with_timeout(active_checks: bool, timeout_secs: u64) -> Config {
    Config {
        max_endpoints: 10,
        concurrency: 2,
        politeness: PolitenessConfig {
            delay_ms: 0,
            retries: 0,
            timeout_secs,
        },
        waf_evasion: WafEvasionConfig {
            enabled: false,
            user_agents: vec![],
        },
        default_headers: vec![],
        cookies: vec![],
        proxy: None,
        danger_accept_invalid_certs: false,
        active_checks,
        dry_run: false,
        stream_findings: false,
        baseline_path: None,
        session_file: None,
        auth_bearer: None,
        auth_basic: None,
        auth_flow: None,
        auth_flow_b: None,
        unauth_strip_headers: vec![],
        per_host_clients: false,
        adaptive_concurrency: false,
        no_discovery: false,
        toggles: ScannerToggles {
            cors: false,
            csp: false,
            graphql: false,
            api_security: false,
            jwt: false,
            openapi: false,
        },
        quiet: false,
    }
}

fn unused_local_url(path: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    format!("http://{}:{}{}", addr.ip(), addr.port(), path)
}

#[tokio::test]
async fn no_rate_limit_detected_reports_low_finding() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/users"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = RateLimitScanner::new(cfg.as_ref());

    let target = format!("{}/api/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "rate_limit/not-detected"),
        "expected no-rate-limit finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn ip_header_bypass_is_reported_when_baseline_hits_429() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/users"))
        .respond_with(|request: &wiremock::Request| {
            let has_spoof_headers = request.headers.get("x-forwarded-for").is_some()
                && request.headers.get("x-real-ip").is_some()
                && request.headers.get("forwarded").is_some();
            if has_spoof_headers {
                ResponseTemplate::new(200).set_body_string("{\"ok\":true}")
            } else {
                ResponseTemplate::new(429).set_body_string("{\"error\":\"rate limited\"}")
            }
        })
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = RateLimitScanner::new(cfg.as_ref());

    let target = format!("{}/api/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "rate_limit/ip-header-bypass"),
        "expected ip-header-bypass finding, got: {findings:#?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.check == "rate_limit/missing-retry-after"),
        "expected missing-retry-after finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn scanner_noop_when_active_checks_disabled() {
    let server = MockServer::start().await;

    let cfg = Arc::new(test_config(false));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = RateLimitScanner::new(cfg.as_ref());

    let target = format!("{}/api/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.is_empty());
}

#[tokio::test]
async fn all_burst_requests_fail_reports_check_failed() {
    let cfg = Arc::new(test_config_with_timeout(true, 1));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = RateLimitScanner::new(cfg.as_ref());

    let target = unused_local_url("/api/users");
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(
        !errors.is_empty(),
        "expected request errors when all burst probes fail"
    );
    assert!(
        findings.iter().any(|f| f.check == "rate_limit/check-failed"),
        "expected check-failed info finding when rate-limit probe cannot execute, got: {findings:#?}"
    );
}
