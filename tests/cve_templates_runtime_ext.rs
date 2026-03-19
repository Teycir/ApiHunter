use std::sync::Arc;

use once_cell::sync::Lazy;
use tempfile::tempdir;
use tokio::sync::Mutex;
use wiremock::matchers::{method, path, path_regex};
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
    let _guard = ENV_LOCK.lock().await;
    let _tmp = tempdir().expect("tempdir");
    let template_path = _tmp.path().join("chain.toml");

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
        _tmp.path().to_str().expect("tmp path"),
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
    let _guard = ENV_LOCK.lock().await;
    let _tmp = tempdir().expect("tempdir");
    let template_path = _tmp.path().join("regex.toml");

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
        _tmp.path().to_str().expect("tmp path"),
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

#[tokio::test]
async fn generic_api_hint_is_ignored_when_specific_hint_exists() {
    let _guard = ENV_LOCK.lock().await;
    let _tmp = tempdir().expect("tempdir");
    let template_path = _tmp.path().join("specific-vs-generic.toml");

    std::fs::write(
        &template_path,
        r#"
[[templates]]
id = "CVE-2099-0102"
check = "cve/cve-2099-0102/specific-hint-priority"
title = "Specific hint priority test"
severity = "medium"
detail = "Specific context hints should be preferred over generic ones."
remediation = "n/a"
source = "test"
path = "/specific-probe"
method = "GET"
status_any_of = [200]
body_contains_any = ["specific-ok"]
context_path_contains_any = ["/api", "/repos"]
"#,
    )
    .expect("write template");

    std::env::set_var(
        "APIHUNTER_CVE_TEMPLATE_DIRS",
        _tmp.path().to_str().expect("tmp path"),
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/specific-probe"))
        .respond_with(ResponseTemplate::new(200).set_body_string("specific-ok"))
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

    std::env::remove_var("APIHUNTER_CVE_TEMPLATE_DIRS");

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .all(|f| f.check != "cve/cve-2099-0102/specific-hint-priority"),
        "template should not match generic '/api' when specific '/repos' is present: {findings:#?}"
    );
    assert!(
        paths.iter().all(|p| p != "/specific-probe"),
        "specific probe should not execute on /api/admin seed: {paths:?}"
    );
}

#[tokio::test]
async fn request_surface_placeholders_are_rejected_at_load() {
    let _guard = ENV_LOCK.lock().await;
    let _tmp = tempdir().expect("tempdir");
    let template_path = _tmp.path().join("placeholder.toml");

    std::fs::write(
        &template_path,
        r#"
[[templates]]
id = "CVE-2099-0103"
check = "cve/cve-2099-0103/unresolved-placeholder"
title = "Placeholder rejection test"
severity = "medium"
detail = "Templates with unresolved request placeholders must be skipped."
remediation = "n/a"
source = "test"
path = "/placeholder/{{bad}}"
method = "GET"
status_any_of = [200]
body_contains_any = ["placeholder-ok"]
context_path_contains_any = ["/placeholderseed"]
"#,
    )
    .expect("write template");

    std::env::set_var(
        "APIHUNTER_CVE_TEMPLATE_DIRS",
        _tmp.path().to_str().expect("tmp path"),
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/placeholder/.*$"))
        .respond_with(ResponseTemplate::new(200).set_body_string("placeholder-ok"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/placeholderseed", server.uri());
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
            .all(|f| f.check != "cve/cve-2099-0103/unresolved-placeholder"),
        "placeholder template should be rejected by loader: {findings:#?}"
    );
    assert!(
        paths.iter().all(|p| !p.starts_with("/placeholder/")),
        "rejected placeholder template should not execute probe requests: {paths:?}"
    );
}

#[tokio::test]
async fn status_only_templates_are_rejected_at_load() {
    let _guard = ENV_LOCK.lock().await;
    let _tmp = tempdir().expect("tempdir");
    let template_path = _tmp.path().join("status-only.toml");

    std::fs::write(
        &template_path,
        r#"
[[templates]]
id = "CVE-2099-0104"
check = "cve/cve-2099-0104/status-only-template"
title = "Status-only matcher rejection test"
severity = "high"
detail = "Templates with only status matcher must be rejected."
remediation = "n/a"
source = "test"
path = "/status-only"
method = "GET"
status_any_of = [200]
body_contains_any = []
body_contains_all = []
body_regex_any = []
body_regex_all = []
match_headers = []
header_regex_any = []
header_regex_all = []
context_path_contains_any = ["/api"]
"#,
    )
    .expect("write template");

    std::env::set_var(
        "APIHUNTER_CVE_TEMPLATE_DIRS",
        _tmp.path().to_str().expect("tmp path"),
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/status-only"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/api/status", server.uri());
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
            .all(|f| f.check != "cve/cve-2099-0104/status-only-template"),
        "status-only template should be rejected: {findings:#?}"
    );
    assert!(
        paths.iter().all(|p| p != "/status-only"),
        "status-only template should not execute probe requests: {paths:?}"
    );
}

#[tokio::test]
async fn templates_without_any_response_matchers_are_rejected_at_load() {
    let _guard = ENV_LOCK.lock().await;
    let _tmp = tempdir().expect("tempdir");
    let template_path = _tmp.path().join("no-matchers.toml");

    std::fs::write(
        &template_path,
        r#"
[[templates]]
id = "CVE-2099-0105"
check = "cve/cve-2099-0105/no-matchers-template"
title = "No matcher rejection test"
severity = "medium"
detail = "Templates without any response matcher must be rejected."
remediation = "n/a"
source = "test"
path = "/no-matchers"
method = "GET"
status_any_of = []
body_contains_any = []
body_contains_all = []
body_regex_any = []
body_regex_all = []
match_headers = []
header_regex_any = []
header_regex_all = []
context_path_contains_any = ["/api"]
"#,
    )
    .expect("write template");

    std::env::set_var(
        "APIHUNTER_CVE_TEMPLATE_DIRS",
        _tmp.path().to_str().expect("tmp path"),
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/no-matchers"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/api/status", server.uri());
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
            .all(|f| f.check != "cve/cve-2099-0105/no-matchers-template"),
        "matcherless template should be rejected: {findings:#?}"
    );
    assert!(
        paths.iter().all(|p| p != "/no-matchers"),
        "matcherless template should not execute probe requests: {paths:?}"
    );
}

#[tokio::test]
async fn root_path_templates_ignore_context_hints() {
    let _guard = ENV_LOCK.lock().await;
    let _tmp = tempdir().expect("tempdir");
    let template_path = _tmp.path().join("root-context.toml");

    std::fs::write(
        &template_path,
        r#"
[[templates]]
id = "CVE-2099-0106"
check = "cve/cve-2099-0106/root-context-normalization"
title = "Root path context normalization test"
severity = "medium"
detail = "Root-path templates should not be filtered by seed path context hints."
remediation = "n/a"
source = "test"
path = "/"
method = "GET"
status_any_of = [200]
body_contains_any = ["root-ok"]
body_contains_all = []
body_regex_any = []
body_regex_all = []
match_headers = []
header_regex_any = []
header_regex_all = []
context_path_contains_any = ["/api"]
"#,
    )
    .expect("write template");

    std::env::set_var(
        "APIHUNTER_CVE_TEMPLATE_DIRS",
        _tmp.path().to_str().expect("tmp path"),
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("root-ok"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = CveTemplateScanner::new(cfg.as_ref());

    let target = format!("{}/", server.uri());
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
            .any(|f| f.check == "cve/cve-2099-0106/root-context-normalization"),
        "root-path template should match non-/api seed paths: {findings:#?}"
    );
    assert!(
        paths.iter().any(|p| p == "/"),
        "expected root probe request for root-path template: {paths:?}"
    );
}
