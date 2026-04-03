use std::sync::Arc;

use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::Confidence,
    scanner::api_security::ApiSecurityScanner,
    scanner::Scanner,
};

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn test_config(active_checks: bool) -> Config {
    Config {
        max_endpoints: 10,
        concurrency: 2,
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
        active_checks,
        dry_run: false,
        response_diff_deep: false,
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
            api_security: true,
            jwt: false,
            openapi: false,
            api_versioning: false,
            grpc_protobuf: false,
            mass_assignment: false,
            oauth_oidc: false,
            rate_limit: false,
            cve_templates: false,
            websocket: false,
        },
        quiet: false,
    }
}

#[tokio::test]
async fn security_txt_probe_runs_once_per_host() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(".*/\\.well-known/security\\.txt$"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(".*/security\\.txt$"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/users"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/users/__canary_404_check_xz9q7"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html><body>spa-shell</body></html>"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/orders"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/orders/__canary_404_check_xz9q7"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html><body>spa-shell</body></html>"),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(false));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiSecurityScanner::new(cfg.as_ref(), None);

    let target_a = format!("{}/api/users", server.uri());
    let (findings_a, errors_a) = scanner.scan(&target_a, &client, cfg.as_ref()).await;
    assert!(
        errors_a.is_empty(),
        "unexpected errors on first scan: {errors_a:#?}"
    );

    let target_b = format!("{}/api/orders", server.uri());
    let (findings_b, errors_b) = scanner.scan(&target_b, &client, cfg.as_ref()).await;
    assert!(
        errors_b.is_empty(),
        "unexpected errors on second scan: {errors_b:#?}"
    );

    let missing_first = findings_a
        .iter()
        .filter(|f| f.check == "api_security/security-txt/missing")
        .count();
    let missing_second = findings_b
        .iter()
        .filter(|f| f.check == "api_security/security-txt/missing")
        .count();
    assert_eq!(
        missing_first, 1,
        "first scan should report missing security.txt"
    );
    assert_eq!(
        missing_second, 0,
        "second scan on same host should skip duplicate security.txt check"
    );

    let requests = server.received_requests().await.expect("received requests");
    let security_txt_hits = requests
        .iter()
        .filter(|r| {
            let p = r.url.path();
            p.ends_with("/.well-known/security.txt") || p.ends_with("/security.txt")
        })
        .count();
    assert_eq!(
        security_txt_hits, 2,
        "expected one host-level security.txt probe set (2 requests), got {security_txt_hits}"
    );
}

#[tokio::test]
async fn authz_matrix_cross_identity_is_reported_for_sensitive_non_numeric_path() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/profile"))
        .and(header("authorization", "Bearer user-a"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"owner":"alice","tier":"gold"}"#),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/profile"))
        .and(header("authorization", "Bearer user-b"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"owner":"alice","tier":"gold"}"#),
        )
        .mount(&server)
        .await;

    let mut cfg_a = test_config(true);
    cfg_a.default_headers = vec![("Authorization".to_string(), "Bearer user-a".to_string())];
    let client_a = HttpClient::new(&cfg_a).expect("http client A");

    let mut cfg_b = cfg_a.clone();
    cfg_b.default_headers = vec![("Authorization".to_string(), "Bearer user-b".to_string())];
    let client_b = Arc::new(HttpClient::new(&cfg_b).expect("http client B"));

    let scanner = ApiSecurityScanner::new(&cfg_a, Some(client_b));
    let target = format!("{}/api/profile", server.uri());
    let (findings, errors) = scanner.scan(&target, &client_a, &cfg_a).await;

    assert!(
        errors.is_empty(),
        "unexpected errors from authz matrix probe: {errors:#?}"
    );

    let finding = findings
        .iter()
        .find(|f| f.check == "api_security/authz-matrix-cross-identity")
        .expect("expected authz matrix cross-identity finding");
    assert_eq!(finding.severity.to_string(), "HIGH");
    assert_eq!(finding.confidence, Some(Confidence::High));
}

#[tokio::test]
async fn idor_cross_user_uses_header_comparison_when_body_differs() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/users/42"))
        .and(header("authorization", "Bearer user-a"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "user-42-v1")
                .set_body_string(r#"{"id":42,"owner":"alice","served_at":"2026-04-03T01:00:00Z"}"#),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/users/42"))
        .and(header("authorization", "Bearer user-b"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "user-42-v1")
                .set_body_string(r#"{"id":42,"owner":"alice","served_at":"2026-04-03T01:00:01Z"}"#),
        )
        .mount(&server)
        .await;

    // Unauthenticated probe should not confirm public exposure here.
    Mock::given(method("GET"))
        .and(path("/api/users/42"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&server)
        .await;

    let mut cfg_a = test_config(true);
    cfg_a.default_headers = vec![("Authorization".to_string(), "Bearer user-a".to_string())];
    let client_a = HttpClient::new(&cfg_a).expect("http client A");

    let mut cfg_b = cfg_a.clone();
    cfg_b.default_headers = vec![("Authorization".to_string(), "Bearer user-b".to_string())];
    let client_b = Arc::new(HttpClient::new(&cfg_b).expect("http client B"));

    let scanner = ApiSecurityScanner::new(&cfg_a, Some(client_b));
    let target = format!("{}/api/users/42", server.uri());
    let (findings, errors) = scanner.scan(&target, &client_a, &cfg_a).await;

    assert!(
        errors.is_empty(),
        "unexpected errors from IDOR cross-user probe: {errors:#?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.check == "api_security/idor-cross-user"),
        "expected idor-cross-user finding when headers match despite body drift, got: {findings:#?}"
    );
}

#[tokio::test]
async fn idor_tier1_uses_header_comparison_when_body_differs() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/orders/42"))
        .and(header("authorization", "Bearer user-a"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "order-42-v1")
                .set_body_string(r#"{"id":42,"state":"open","served_at":"2026-04-03T01:10:00Z"}"#),
        )
        .with_priority(1)
        .mount(&server)
        .await;

    // Unauthenticated response differs in body but keeps the same stable ETag.
    Mock::given(method("GET"))
        .and(path("/api/orders/42"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "order-42-v1")
                .set_body_string(r#"{"id":42,"state":"open","served_at":"2026-04-03T01:10:01Z"}"#),
        )
        .with_priority(10)
        .mount(&server)
        .await;

    let mut cfg = test_config(true);
    cfg.default_headers = vec![("Authorization".to_string(), "Bearer user-a".to_string())];
    let cfg = Arc::new(cfg);
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiSecurityScanner::new(cfg.as_ref(), None);
    let target = format!("{}/api/orders/42", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "api_security/unauthenticated-access"),
        "expected unauthenticated-access finding based on header comparison, got: {findings:#?}"
    );
    assert!(
        findings
            .iter()
            .all(|f| f.check != "api_security/partial-unauth-access"),
        "did not expect partial-unauth-access when comparison headers match, got: {findings:#?}"
    );
}

#[tokio::test]
async fn blind_ssrf_probe_dispatches_once_for_same_host_path() {
    let _guard = ENV_LOCK.lock().await;
    let previous = std::env::var("APIHUNTER_OAST_BASE").ok();
    std::env::set_var("APIHUNTER_OAST_BASE", "https://oast.example.test");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/image-proxy"))
        .respond_with(ResponseTemplate::new(202).set_body_string(r#"{"queued":true}"#))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiSecurityScanner::new(cfg.as_ref(), None);
    let target = format!("{}/api/image-proxy", server.uri());

    let (first_findings, first_errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let (_second_findings, second_errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    if let Some(value) = previous {
        std::env::set_var("APIHUNTER_OAST_BASE", value);
    } else {
        std::env::remove_var("APIHUNTER_OAST_BASE");
    }

    assert!(
        first_errors.is_empty() && second_errors.is_empty(),
        "unexpected blind SSRF errors: first={first_errors:#?} second={second_errors:#?}"
    );
    assert!(
        first_findings
            .iter()
            .any(|finding| finding.check == "api_security/blind-ssrf-probe-dispatched"),
        "expected blind SSRF dispatched finding, got: {first_findings:#?}"
    );

    let requests = server.received_requests().await.expect("received requests");
    let probe_hits = requests
        .iter()
        .filter(|request| {
            request.url.path() == "/api/image-proxy"
                && request
                    .url
                    .query()
                    .map(|query| query.contains("oast.example.test"))
                    .unwrap_or(false)
        })
        .count();
    assert!(
        (1..=4).contains(&probe_hits),
        "expected 1..=4 blind SSRF probe hits for deduped host/path, got {probe_hits}"
    );
}

#[tokio::test]
async fn blind_ssrf_reflection_is_reported() {
    let _guard = ENV_LOCK.lock().await;
    let previous = std::env::var("APIHUNTER_OAST_BASE").ok();
    std::env::set_var("APIHUNTER_OAST_BASE", "https://oast.example.test");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/fetch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("callback accepted: https://oast.example.test/token"),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiSecurityScanner::new(cfg.as_ref(), None);
    let target = format!("{}/api/fetch", server.uri());

    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    if let Some(value) = previous {
        std::env::set_var("APIHUNTER_OAST_BASE", value);
    } else {
        std::env::remove_var("APIHUNTER_OAST_BASE");
    }

    assert!(
        errors.is_empty(),
        "unexpected blind SSRF reflection errors: {errors:#?}"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "api_security/blind-ssrf-token-reflected"),
        "expected blind SSRF reflection finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn blind_ssrf_dry_run_does_not_dispatch_requests() {
    let _guard = ENV_LOCK.lock().await;
    let previous = std::env::var("APIHUNTER_OAST_BASE").ok();
    std::env::set_var("APIHUNTER_OAST_BASE", "https://oast.example.test");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/image-proxy"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .mount(&server)
        .await;

    let mut cfg = test_config(true);
    cfg.dry_run = true;
    let cfg = Arc::new(cfg);
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiSecurityScanner::new(cfg.as_ref(), None);
    let target = format!("{}/api/image-proxy", server.uri());

    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    if let Some(value) = previous {
        std::env::set_var("APIHUNTER_OAST_BASE", value);
    } else {
        std::env::remove_var("APIHUNTER_OAST_BASE");
    }

    assert!(
        errors.is_empty(),
        "unexpected blind SSRF dry-run errors: {errors:#?}"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "api_security/blind-ssrf-probe-dry-run"),
        "expected blind SSRF dry-run finding, got: {findings:#?}"
    );

    let requests = server.received_requests().await.expect("received requests");
    let probe_hits = requests
        .iter()
        .filter(|request| {
            request.url.path() == "/api/image-proxy"
                && request
                    .url
                    .query()
                    .map(|query| query.contains("oast.example.test"))
                    .unwrap_or(false)
        })
        .count();
    assert_eq!(
        probe_hits, 0,
        "expected zero dispatched blind SSRF requests in dry-run mode"
    );
}

#[tokio::test]
async fn gateway_signal_is_detected_from_response_headers() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/orders"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("x-kong-proxy-latency", "7")
                .set_body_string(r#"{"orders":[]}"#),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(false));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiSecurityScanner::new(cfg.as_ref(), None);
    let target = format!("{}/api/orders", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "api_security/gateway-detected"),
        "expected gateway detection finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn gateway_bypass_probe_reports_status_flip() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/private"))
        .and(header("x-original-url", "/api/private"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .with_priority(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/private"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .with_priority(10)
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiSecurityScanner::new(cfg.as_ref(), None);
    let target = format!("{}/api/private", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "api_security/gateway-bypass-suspected"),
        "expected gateway bypass finding, got: {findings:#?}"
    );
}
