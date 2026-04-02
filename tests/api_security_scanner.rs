use std::sync::Arc;

use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::Confidence,
    scanner::api_security::ApiSecurityScanner,
    scanner::Scanner,
};

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
