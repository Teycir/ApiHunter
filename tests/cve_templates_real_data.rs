use std::{fs, path::PathBuf, sync::Arc};

use wiremock::matchers::{header, method, path, query_param};
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
            api_security: false,
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

fn fixture(path: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/real_cve_payloads");
    p.push(path);
    let bytes =
        fs::read(&p).unwrap_or_else(|e| panic!("failed to read fixture '{}': {e}", p.display()));
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn cve_2022_22947_matches_real_gateway_response_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/actuator/gateway/routes"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(fixture("cve-2022-22947-body.json")),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());
    let target = format!("{}/actuator", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2022-22947/spring-cloud-gateway-actuator-exposed"),
        "expected CVE-2022-22947 finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn cve_2021_29442_matches_real_nacos_response_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nacos/v1/auth/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(fixture("cve-2021-29442-body.json")),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());
    let target = format!("{}/nacos", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2021-29442/nacos-auth-bypass-signal"),
        "expected CVE-2021-29442 finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn cve_2021_29441_matches_real_baseline_and_bypass_fixtures() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nacos/v1/auth/users"))
        .and(header("user-agent", "Nacos-Server"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(fixture("cve-2021-29441-bypass-body.json")),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/nacos/v1/auth/users"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("content-type", "application/json")
                .set_body_string(fixture("cve-2021-29441-baseline-body.json")),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());
    let target = format!("{}/nacos", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2021-29441/nacos-user-agent-auth-bypass-signal"),
        "expected CVE-2021-29441 finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn cve_2020_13945_matches_real_apisix_admin_response_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/apisix/admin/routes"))
        .and(header("x-api-key", "edd1c9f034335f136f87ad84b625c8f1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(fixture("cve-2020-13945-body.json")),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());
    let target = format!("{}/apisix/admin", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2020-13945/apisix-default-admin-key"),
        "expected CVE-2020-13945 finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn cve_2021_45232_matches_real_apisix_dashboard_response_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/apisix/admin/migrate/export"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(fixture("cve-2021-45232-body.json")),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());
    let target = format!("{}/apisix/admin", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2021-45232/apisix-dashboard-unauthorized-export"),
        "expected CVE-2021-45232 finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn cve_2022_24288_matches_real_airflow_223_source_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin/airflow/code"))
        .and(query_param("root", ""))
        .and(query_param(
            "dag_id",
            "example_passing_params_via_test_command",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(fixture("cve-2022-24288-body.py")),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());
    let target = format!("{}/admin/airflow", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2022-24288/airflow-example-dag-params-rce-signal"),
        "expected CVE-2022-24288 finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn cve_2022_24288_does_not_match_real_airflow_224_patched_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin/airflow/code"))
        .and(query_param("root", ""))
        .and(query_param(
            "dag_id",
            "example_passing_params_via_test_command",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(fixture("nonmatch-cve-2022-24288-airflow-2.2.4-body.py")),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());
    let target = format!("{}/admin/airflow", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .all(|f| f.check != "cve/cve-2022-24288/airflow-example-dag-params-rce-signal"),
        "did not expect CVE-2022-24288 finding on patched fixture: {findings:#?}"
    );
}

#[tokio::test]
async fn cve_2022_22947_does_not_match_real_dashboard_html_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/actuator/gateway/routes"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(fixture("nonmatch-apisix-dashboard-actuator-routes.html")),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());
    let target = format!("{}/apisix/admin", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .all(|f| f.check != "cve/cve-2022-22947/spring-cloud-gateway-actuator-exposed"),
        "did not expect CVE-2022-22947 finding on real dashboard html fixture: {findings:#?}"
    );
}
