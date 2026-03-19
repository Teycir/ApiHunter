// tests/integration_runner.rs
//
// Round-trip integration tests: spin up a real HTTP mock server (wiremock),
// build a genuine Config + HttpClient, call runner::run(), and assert on the
// returned findings / errors.

use std::sync::Arc;
use std::time::Duration;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::{ReportConfig, ReportFormat, Reporter, Severity},
    runner::{self, RuntimeMetrics},
};

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal Config suitable for tests.
fn test_config() -> Config {
    Config {
        max_endpoints: 100,
        concurrency: 4,
        politeness: PolitenessConfig {
            delay_ms: 0,
            retries: 0,
            timeout_secs: 5,
        },
        waf_evasion: WafEvasionConfig {
            enabled: false,
            user_agents: vec![],
        },
        default_headers: vec![],
        cookies: vec![],
        proxy: None,
        danger_accept_invalid_certs: false,
        active_checks: false,
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
            cors: true,
            csp: true,
            graphql: true,
            api_security: true,
            jwt: true,
            openapi: true,
            mass_assignment: true,
            oauth_oidc: true,
            rate_limit: true,
            cve_templates: true,
            websocket: true,
        },
        quiet: false,
    }
}

fn test_reporter() -> Arc<Reporter> {
    Arc::new(
        Reporter::new(ReportConfig {
            format: ReportFormat::Pretty,
            output_path: None,
            print_summary: false,
            quiet: true,
            stream: false,
        })
        .expect("reporter"),
    )
}

// ─── CORS tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn cors_wildcard_origin_detected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "*")
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    // OPTIONS probe for CORS
    Mock::given(method("OPTIONS"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "*")
                .insert_header("Access-Control-Allow-Methods", "GET, POST"),
        )
        .mount(&server)
        .await;

    let config = Arc::new(test_config());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let reporter = test_reporter();

    let result = runner::run(vec![server.uri()], config, client, None, reporter, false).await;

    let cors_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.scanner == "cors")
        .collect();

    assert!(
        !cors_findings.is_empty(),
        "expected at least one CORS finding; got: {:#?}",
        result.findings
    );
    assert!(
        result
            .metrics
            .scanner_findings
            .get("cors")
            .copied()
            .unwrap_or(0)
            >= 1
    );
    assert!(result.metrics.http_requests >= 1);
}

#[tokio::test]
async fn cors_no_headers_no_finding() {
    let server = MockServer::start().await;

    // No CORS headers → no CORS finding expected.
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = Arc::new(test_config());
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![server.uri()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    let cors_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.scanner == "cors")
        .collect();

    assert!(
        cors_findings.is_empty(),
        "no-CORS-header endpoint should produce no CORS findings; got: {cors_findings:#?}"
    );
}

// ─── CSP tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn csp_missing_header_detected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    // Needed for method probing
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = Arc::new(test_config());
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![server.uri()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    let has_csp_missing = result
        .findings
        .iter()
        .any(|f| f.scanner == "csp" && f.check.contains("missing"));

    assert!(has_csp_missing, "missing CSP header should be reported");
}

#[tokio::test]
async fn csp_unsafe_inline_detected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .insert_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'unsafe-inline'",
                )
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = Arc::new(test_config());
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![server.uri()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    let has_unsafe = result
        .findings
        .iter()
        .any(|f| f.scanner == "csp" && f.title.to_lowercase().contains("unsafe-inline"));
    assert!(has_unsafe, "'unsafe-inline' in CSP should be flagged");
}

// ─── API security: debug endpoint false-positive guards ───────────────────────

#[tokio::test]
async fn api_security_spa_catchall_suppresses_false_positive() {
    // Simulate an SPA that returns 200 + HTML for every path.
    let server = MockServer::start().await;

    let spa_body = "<html><head><title>SPA</title></head><body><div id='root'></div></body></html>";

    // Catch-all: every GET returns the SPA shell.
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html; charset=utf-8")
                .set_body_string(spa_body),
        )
        .mount(&server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;

    // Only enable api_security scanner for this test.
    let mut cfg = test_config();
    cfg.toggles.cors = false;
    cfg.toggles.csp = false;
    cfg.toggles.graphql = false;
    let config = Arc::new(cfg);
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![server.uri()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    // SPA catch-all guard should suppress all debug-endpoint false positives.
    let debug_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.check.contains("debug-endpoint"))
        .collect();

    assert!(
        debug_findings.is_empty(),
        "SPA catch-all should suppress debug endpoint false positives; got: {debug_findings:#?}"
    );
}

#[tokio::test]
async fn api_security_real_env_file_detected() {
    let server = MockServer::start().await;

    // Root returns a normal page.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html><body>Hello</body></html>"),
        )
        .mount(&server)
        .await;

    // Canary returns 404 (not an SPA).
    Mock::given(method("GET"))
        .and(path("/__canary_404_check_xz9q7"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    // Real .env file.
    Mock::given(method("GET"))
        .and(path("/.env"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_string(
                    "DB_HOST=localhost\nDB_USER=admin\nDB_PASS=supersecret\nAPP_KEY=base64:abc123\n",
                ),
        )
        .mount(&server)
        .await;

    // All other debug paths return 404.
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;

    let mut cfg = test_config();
    cfg.toggles.cors = false;
    cfg.toggles.csp = false;
    cfg.toggles.graphql = false;
    let config = Arc::new(cfg);
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![server.uri()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    let env_finding = result.findings.iter().any(|f| f.check.contains(".env"));

    assert!(
        env_finding,
        "A real .env file with KEY=VALUE content should be detected"
    );
}

#[tokio::test]
async fn api_security_spa_canary_probe_errors_are_reported() {
    let server = MockServer::start().await;

    for canary in [
        "/__canary_404_check_xz9q7",
        "/_canary_test_404",
        "/xyzabc123notfound",
    ] {
        Mock::given(method("GET"))
            .and(path(canary))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&server)
            .await;
    }

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;

    let mut cfg = test_config();
    cfg.politeness.timeout_secs = 1;
    cfg.toggles.cors = false;
    cfg.toggles.csp = false;
    cfg.toggles.graphql = false;
    cfg.toggles.jwt = false;
    cfg.toggles.openapi = false;
    let config = Arc::new(cfg);
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![server.uri()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    assert!(
        result
            .errors
            .iter()
            .any(|e| e.message.contains("spa_canary_probe")),
        "expected SPA canary probe failures to be surfaced in errors, got: {:#?}",
        result.errors
    );
}

#[tokio::test]
async fn api_security_id_range_request_errors_are_not_counted_as_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"id":42,"owner":"alice","profile":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#,
        ))
        .mount(&server)
        .await;

    for timeout_path in ["/users/40", "/users/44"] {
        Mock::given(method("GET"))
            .and(path(timeout_path))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&server)
            .await;
    }

    for forbidden_path in ["/users/41", "/users/43"] {
        Mock::given(method("GET"))
            .and(path(forbidden_path))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
    }

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;

    let mut cfg = test_config();
    cfg.active_checks = true;
    cfg.no_discovery = true;
    cfg.politeness.timeout_secs = 1;
    cfg.toggles.cors = false;
    cfg.toggles.csp = false;
    cfg.toggles.graphql = false;
    cfg.toggles.jwt = false;
    cfg.toggles.openapi = false;
    let config = Arc::new(cfg);
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let target = format!("{}/users/42", server.uri());
    let result = runner::run(vec![target], config, client, None, test_reporter(), false).await;

    assert!(
        result
            .findings
            .iter()
            .all(|f| f.check != "api_security/idor-id-enumerable"),
        "IDOR enumerable finding should not trigger when adjacent IDs are only 403/timeouts, got: {:#?}",
        result.findings
    );
    assert!(
        !result.errors.is_empty(),
        "expected timeout errors from range probes to be captured"
    );
}

#[tokio::test]
async fn api_security_id_range_severity_scales_with_success_breadth() {
    let server = MockServer::start().await;

    for id in 40..=44 {
        let path_value = format!("/users/{id}");
        let body = format!(
            r#"{{"id":{},"owner":"user{}","profile":"{}"}}"#,
            id,
            id,
            "x".repeat(72)
        );

        Mock::given(method("GET"))
            .and(path(path_value))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
    }

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;

    let mut cfg = test_config();
    cfg.active_checks = true;
    cfg.no_discovery = true;
    cfg.toggles.cors = false;
    cfg.toggles.csp = false;
    cfg.toggles.graphql = false;
    cfg.toggles.jwt = false;
    cfg.toggles.openapi = false;
    cfg.toggles.mass_assignment = false;
    cfg.toggles.oauth_oidc = false;
    cfg.toggles.rate_limit = false;
    cfg.toggles.cve_templates = false;
    cfg.toggles.websocket = false;
    let config = Arc::new(cfg);
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let target = format!("{}/users/42", server.uri());
    let result = runner::run(vec![target], config, client, None, test_reporter(), false).await;

    let idor = result
        .findings
        .iter()
        .find(|f| f.check == "api_security/idor-id-enumerable")
        .expect("expected IDOR enumerable finding");

    assert_eq!(
        idor.severity,
        Severity::Critical,
        "all adjacent IDs successful should escalate severity"
    );
    assert!(
        idor.detail.contains("4 adjacent IDs"),
        "detail should include observed success breadth, got: {}",
        idor.detail
    );
}

// ─── Runner behaviour tests ───────────────────────────────────────────────────

#[tokio::test]
async fn runner_handles_connection_error_gracefully() {
    // Point at an unreachable address — runner must not panic.
    let config = Arc::new(test_config());
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec!["http://127.0.0.1:1".to_string()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    // Runner returned without panicking — that's the assertion.
    // Errors should be captured.
    assert!(
        !result.errors.is_empty() || result.findings.is_empty(),
        "unreachable host should produce errors or no findings"
    );
}

#[tokio::test]
async fn runner_aggregates_findings_across_scanners() {
    let server = MockServer::start().await;

    // Trigger CORS + CSP findings simultaneously.
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .insert_header("Access-Control-Allow-Origin", "*")
                // No CSP → csp scanner fires
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(200).insert_header("Access-Control-Allow-Origin", "*"))
        .mount(&server)
        .await;

    let config = Arc::new(test_config());
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![server.uri()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    let scanners_reported: std::collections::HashSet<&str> =
        result.findings.iter().map(|f| f.scanner.as_str()).collect();

    assert!(
        scanners_reported.contains("cors"),
        "expected CORS finding; got scanners: {scanners_reported:?}"
    );
    assert!(
        scanners_reported.contains("csp") || scanners_reported.contains("api_security"),
        "expected CSP or api_security finding; got scanners: {scanners_reported:?}"
    );
}

#[tokio::test]
async fn runner_returns_scanned_count() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = Arc::new(test_config());
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![server.uri()],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    assert_eq!(result.scanned, 1, "should report 1 URL scanned");
}

#[tokio::test]
async fn discovery_runs_once_per_site_not_per_seed() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_string("User-agent: *\nDisallow:\n"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut cfg = test_config();
    cfg.toggles.cors = false;
    cfg.toggles.csp = false;
    cfg.toggles.graphql = false;
    cfg.toggles.api_security = false;
    cfg.toggles.jwt = false;
    cfg.toggles.openapi = false;
    cfg.max_endpoints = 1;

    let config = Arc::new(cfg);
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let url_a = format!("{}/alpha", server.uri());
    let url_b = format!("{}/beta", server.uri());

    let _ = runner::run(
        vec![url_a, url_b],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;
}

#[tokio::test]
async fn no_discovery_skips_robots_probe() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_string("User-agent: *\nDisallow:\n"),
        )
        .expect(0)
        .mount(&server)
        .await;

    let mut cfg = test_config();
    cfg.no_discovery = true;
    cfg.toggles.cors = false;
    cfg.toggles.csp = false;
    cfg.toggles.graphql = false;
    cfg.toggles.api_security = false;
    cfg.toggles.jwt = false;
    cfg.toggles.openapi = false;
    cfg.active_checks = false;

    let config = Arc::new(cfg);
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let url_a = format!("{}/alpha", server.uri());
    let url_b = format!("{}/beta", server.uri());

    let result = runner::run(
        vec![url_a, url_b],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    assert_eq!(result.scanned, 2, "seed URLs should be scanned directly");
}

#[tokio::test]
async fn canonicalise_dedups_query_parameter_order_variants() {
    let mut cfg = test_config();
    cfg.no_discovery = true;
    cfg.toggles.cors = false;
    cfg.toggles.csp = false;
    cfg.toggles.graphql = false;
    cfg.toggles.api_security = false;
    cfg.toggles.jwt = false;
    cfg.toggles.openapi = false;
    cfg.toggles.mass_assignment = false;
    cfg.toggles.oauth_oidc = false;
    cfg.toggles.rate_limit = false;
    cfg.toggles.cve_templates = false;
    cfg.toggles.websocket = false;

    let config = Arc::new(cfg);
    let client = Arc::new(HttpClient::new(&config).unwrap());

    let result = runner::run(
        vec![
            "https://api.example.test/users?page=1&limit=10".to_string(),
            "https://api.example.test/users?limit=10&page=1".to_string(),
        ],
        config,
        client,
        None,
        test_reporter(),
        false,
    )
    .await;

    assert_eq!(result.scanned, 1, "query-order variants should deduplicate");
    assert_eq!(result.skipped, 1, "one duplicate URL should be skipped");
}

// ─── Reporter unit-level tests ────────────────────────────────────────────────

mod reporter_tests {
    use super::*;
    use api_scanner::reports::{exit_code, Finding, ReportSummary};
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn reporter_writes_pretty_json_to_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let cfg = ReportConfig {
            format: ReportFormat::Pretty,
            output_path: Some(path.clone()),
            print_summary: false,
            quiet: true,
            stream: false,
        };

        let reporter = Reporter::new(cfg).unwrap();
        let result = runner::RunResult {
            findings: vec![Finding::new(
                "https://example.com",
                "cors.wildcard",
                "Wildcard CORS",
                Severity::High,
                "Access-Control-Allow-Origin: *",
                "cors",
            )],
            errors: vec![],
            elapsed: std::time::Duration::from_millis(420),
            scanned: 1,
            skipped: 0,
            metrics: RuntimeMetrics::default(),
        };

        reporter.write_run_result(&result);
        reporter.finalize();

        let mut content = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        let doc: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert!(doc.get("findings").is_some());
        assert!(doc.get("summary").is_some());
        assert_eq!(doc["summary"]["total"], 1);
    }

    #[test]
    fn exit_code_clean() {
        let s = ReportSummary::default();
        assert_eq!(exit_code(&s, &Severity::High), 0);
    }

    #[test]
    fn exit_code_with_findings() {
        let s = ReportSummary {
            high: 1,
            total: 1,
            ..Default::default()
        };
        assert_eq!(exit_code(&s, &Severity::High), 1);
    }

    #[test]
    fn exit_code_with_errors() {
        let s = ReportSummary {
            errors: 3,
            ..Default::default()
        };
        assert_eq!(exit_code(&s, &Severity::High), 2);
    }
}
