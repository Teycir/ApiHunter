use std::sync::Arc;

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::{api_versioning::ApiVersioningScanner, Scanner},
};
use wiremock::{
    matchers::{method, path, query_param, query_param_is_missing},
    Mock, MockServer, ResponseTemplate,
};

fn test_config() -> Config {
    Config {
        max_endpoints: 10,
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
            cors: false,
            csp: false,
            graphql: false,
            api_security: false,
            jwt: false,
            openapi: false,
            api_versioning: true,
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
async fn detects_version_headers_legacy_versions_and_query_variant_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/users"))
        .and(query_param_is_missing("apihunter_diff_probe"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("x-api-version", "2.0")
                .insert_header("deprecation", "true")
                .set_body_string(
                    r#"{"users":[{"id":1,"role":"user"}],"meta":{"cursor":"a1b2c3d4"}}"#,
                ),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v2/users"))
        .and(query_param("apihunter_diff_probe", "1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(
                    r#"{"users":[{"id":1,"role":"user"}],"meta":{"cursor":"a1b2c3d4"}}"#,
                ),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v3/users"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiVersioningScanner::new(cfg.as_ref());

    let target = format!("{}/api/v2/users", server.uri());
    let (findings, _errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(findings
        .iter()
        .any(|finding| finding.check == "api_versioning/version-header-disclosed"));
    assert!(findings
        .iter()
        .any(|finding| finding.check == "api_versioning/multiple-active-versions"));
    assert!(findings
        .iter()
        .any(|finding| finding.check == "api_versioning/legacy-version-still-accessible"));
    assert!(findings
        .iter()
        .any(|finding| finding.check == "response_diff/query-variant-server-error"));
}

#[tokio::test]
async fn detects_response_error_drift_across_version_variants() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/orders"))
        .and(query_param_is_missing("apihunter_diff_probe"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(
                    r#"{"orders":[{"id":99,"state":"completed","total":1200}],"meta":{"source":"api","format":"json"}}"#,
                ),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v2/orders"))
        .and(query_param("apihunter_diff_probe", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(
                    r#"{"orders":[{"id":99,"state":"completed","total":1200}],"meta":{"source":"api","format":"json"}}"#,
                ),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/orders"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/plain")
                .set_body_string("legacy upstream handler failure"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v3/orders"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = ApiVersioningScanner::new(cfg.as_ref());

    let target = format!("{}/api/v2/orders", server.uri());
    let (findings, _errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "response_diff/version-variant-server-error"),
        "expected version-variant server error finding, got {findings:#?}"
    );
}
