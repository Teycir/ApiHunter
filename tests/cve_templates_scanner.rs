use std::sync::Arc;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::cve_templates::CveTemplateScanner,
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
            api_security: false,
            jwt: false,
            openapi: false,
        },
        quiet: false,
    }
}

#[tokio::test]
async fn translated_template_detects_gateway_actuator_exposure() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/actuator/gateway/routes"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"routes":[{"id":"r1","predicates":[],"filters":[]}]}"#),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/api/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");
    let paths = requests
        .iter()
        .map(|r| r.url.path().to_string())
        .collect::<Vec<_>>();

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| { f.check == "cve/cve-2022-22947/spring-cloud-gateway-actuator-exposed" }),
        "expected translated CVE finding, got: {findings:#?}; requests={paths:?}"
    );
}

#[tokio::test]
async fn translated_template_22947_does_not_match_html_routes_text() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/actuator/gateway/routes"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(
                    "<html><body>dashboard routes page without predicate or route id</body></html>",
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!(
        "{}/actuator",
        server.uri().replace("127.0.0.1", "localhost")
    );
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .all(|f| f.check != "cve/cve-2022-22947/spring-cloud-gateway-actuator-exposed"),
        "did not expect 22947 finding on html routes text: {findings:#?}"
    );
}

#[tokio::test]
async fn translated_template_sends_required_header_for_apisix_probe() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/apisix/admin/routes"))
        .and(header("x-api-key", "edd1c9f034335f136f87ad84b625c8f1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"routes":[{"id":"1","uri":"/api","upstream":{"node":[]}}]}"#),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/api/admin", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");
    let paths = requests
        .iter()
        .map(|r| r.url.path().to_string())
        .collect::<Vec<_>>();

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2020-13945/apisix-default-admin-key"),
        "expected APISIX CVE finding, got: {findings:#?}; requests={paths:?}"
    );
}

#[tokio::test]
async fn translated_template_detects_apisix_dashboard_export_exposure() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/apisix/admin/migrate/export"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"Consumers":[],"Routes":[]}"#),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/api/routes", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2021-45232/apisix-dashboard-unauthorized-export"),
        "expected APISIX dashboard CVE finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn translated_template_detects_cisco_asa_portal_lfi_signal() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/+CSCOT+/translation-table"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(
                    r#"if (INTERNAL_PASSWORD_ENABLED) { return CONF_VIRTUAL_KEYBOARD; }"#,
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/translation-table", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2020-3452/cisco-asa-ftd-path-traversal-signal"),
        "expected Cisco ASA CVE finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn translated_template_detects_nacos_user_agent_bypass_with_baseline() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/nacos/v1/auth/users"))
        .and(header("user-agent", "Nacos-Server"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"totalCount":1,"pageItems":[{"username":"nacos"}]}"#),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/nacos/v1/auth/users"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"message":"Forbidden"}"#),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/nacos/v1/auth/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2021-29441/nacos-user-agent-auth-bypass-signal"),
        "expected Nacos User-Agent bypass CVE finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn scanner_noop_when_active_checks_disabled() {
    let server = MockServer::start().await;

    let cfg = Arc::new(test_config(false));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/api/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.is_empty());
}
