use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::cve_templates::CveTemplateScanner,
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
            mass_assignment: false,
            oauth_oidc: false,
            rate_limit: false,
            cve_templates: true,
            websocket: false,
        },
        quiet: false,
    }
}

#[tokio::test]
async fn preflight_chain_executes_before_probe() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let tmp = tempdir().expect("tempdir");
    let template_path = tmp.path().join("chain.toml");

    std::fs::write(
        &template_path,
        r#"
[[templates]]
id = "CVE-2099-0100"
check = "cve/cve-2099-0100/chain-support"
title = "Chain support test"
severity = "medium"
detail = "Chain test"
remediation = "n/a"
source = "test"
path = "/probe"
method = "GET"
status_any_of = [200]
body_contains_any = ["probe-ok"]
context_path_contains_any = ["/chainseed"]

[[templates.preflight_requests]]
path = "/warmup"
method = "GET"
expect_status_any_of = [200]
"#,
    )
    .expect("write template");

    std::env::set_var(
        "APIHUNTER_CVE_TEMPLATE_DIRS",
        tmp.path().to_str().expect("tmp path"),
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/warmup"))
        .respond_with(ResponseTemplate::new(200).set_body_string("warmup"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/probe"))
        .respond_with(ResponseTemplate::new(200).set_body_string("probe-ok"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/chainseed", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");
    let paths = requests
        .iter()
        .map(|r| r.url.path().to_string())
        .collect::<Vec<_>>();

    std::env::remove_var("APIHUNTER_CVE_TEMPLATE_DIRS");

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2099-0100/chain-support"),
        "expected finding with chain template: {findings:#?}"
    );
    let warmup_pos = paths.iter().position(|p| p == "/warmup");
    let probe_pos = paths.iter().position(|p| p == "/probe");
    assert!(warmup_pos.is_some(), "expected preflight warmup request");
    assert!(probe_pos.is_some(), "expected main probe request");
    assert!(
        warmup_pos < probe_pos,
        "expected preflight warmup before main probe; paths={paths:?}"
    );
}

#[tokio::test]
async fn regex_constraints_match_for_body_and_headers() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let tmp = tempdir().expect("tempdir");
    let template_path = tmp.path().join("regex.toml");

    std::fs::write(
        &template_path,
        r#"
[[templates]]
id = "CVE-2099-0101"
check = "cve/cve-2099-0101/regex-support"
title = "Regex support test"
severity = "medium"
detail = "Regex matching test"
remediation = "n/a"
source = "test"
path = "/regex"
method = "GET"
status_any_of = [200]
body_regex_all = ["(?i)token_[a-z0-9]+"]
header_regex_all = ["(?i)x-powered-by:\\s*express"]
context_path_contains_any = ["/api"]
"#,
    )
    .expect("write template");

    std::env::set_var(
        "APIHUNTER_CVE_TEMPLATE_DIRS",
        tmp.path().to_str().expect("tmp path"),
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/regex"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-powered-by", "Express")
                .set_body_string("token_abcd42"),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/api/status", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    std::env::remove_var("APIHUNTER_CVE_TEMPLATE_DIRS");

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "cve/cve-2099-0101/regex-support"),
        "expected regex-constrained finding: {findings:#?}"
    );
}
