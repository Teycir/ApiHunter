use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

mod helpers;

use helpers::{assert_finding_exists, mock_json_response};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::Severity,
    scanner::mass_assignment::MassAssignmentScanner,
    scanner::Scanner,
};

fn test_config(active_checks: bool) -> Config {
    test_config_with_timeout(active_checks, 5)
}

fn test_config_with_timeout(active_checks: bool, timeout_secs: u64) -> Config {
    test_config_custom(active_checks, false, timeout_secs)
}

fn test_config_custom(active_checks: bool, dry_run: bool, timeout_secs: u64) -> Config {
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
        dry_run,
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
            cve_templates: false,
            websocket: false,
        },
        quiet: false,
    }
}

fn assert_expected_mass_assignment_payload(
    requests: &[wiremock::Request],
    expected_path: &str,
    expected_post_count: usize,
) {
    let posts = requests
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == expected_path)
        .collect::<Vec<_>>();
    assert_eq!(
        posts.len(),
        expected_post_count,
        "unexpected POST request count at {expected_path}; got {}",
        posts.len()
    );

    for req in posts {
        let content_type = req
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type
                .to_ascii_lowercase()
                .starts_with("application/json"),
            "expected JSON POST content-type header, got: {content_type}"
        );

        let body: serde_json::Value =
            serde_json::from_slice(&req.body).expect("POST body should be JSON");
        assert_eq!(
            body.get("is_admin"),
            Some(&json!(true)),
            "expected probe payload to include is_admin=true"
        );
        assert_eq!(
            body.get("role"),
            Some(&json!("admin")),
            "expected probe payload to include role=admin"
        );
        assert_eq!(
            body.get("permissions"),
            Some(&json!(["*"])),
            "expected probe payload to include permissions=[\"*\"]"
        );
    }
}

#[tokio::test]
async fn reflected_sensitive_fields_are_reported() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(mock_json_response(
            200,
            r#"{"user":{"id":1,"is_admin":false,"role":"user"}}"#,
        ))
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(mock_json_response(
            200,
            r#"{"ok":true,"is_admin":true,"role":"admin","permissions":["*"]}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert_finding_exists(
        &findings,
        "mass_assignment/reflected-fields",
        Severity::Medium,
    );
    assert_expected_mass_assignment_payload(&requests, "/users", 1);
}

#[tokio::test]
async fn persisted_sensitive_fields_are_reported_as_high_severity() {
    let server = MockServer::start().await;

    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_for_get = Arc::clone(&call_count);

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(move |_request: &wiremock::Request| {
            let call = call_count_for_get.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"user":{"id":1,"name":"baseline"}}"#)
            } else {
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(
                        r#"{"user":{"id":1,"is_admin":true,"role":"admin","permissions":["*"]}}"#,
                    )
            }
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(
                    r#"{"ok":true,"is_admin":true,"role":"admin","permissions":["*"]}"#,
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");
    let method_path = requests
        .iter()
        .map(|r| format!("{} {}", r.method.as_str(), r.url.path()))
        .collect::<Vec<_>>();

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one finding type (high OR medium), got: {findings:#?}"
    );
    assert_eq!(
        findings[0].check, "mass_assignment/persisted-state-change",
        "expected confirmed mass-assignment finding, got: {findings:#?}"
    );
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "expected exactly two GET baseline/confirm calls"
    );
    assert!(
        method_path
            .windows(3)
            .any(|w| { w[0] == "GET /users" && w[1] == "POST /users" && w[2] == "GET /users" }),
        "expected GET -> POST -> GET call order, got: {method_path:?}"
    );
    assert_expected_mass_assignment_payload(&requests, "/users", 1);
}

#[tokio::test]
async fn partial_reflection_still_reports_finding() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"user":{"id":1,"role":"user"}}"#),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"ok":true,"role":"admin"}"#),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    let finding = findings
        .iter()
        .find(|f| f.check == "mass_assignment/reflected-fields")
        .expect("expected reflected finding");
    assert!(
        finding.evidence.as_deref().unwrap_or("").contains("role"),
        "expected reflected role evidence, got: {}",
        finding.evidence.as_deref().unwrap_or("-")
    );
    assert_expected_mass_assignment_payload(&requests, "/users", 1);
}

#[tokio::test]
async fn non_json_post_response_is_ignored() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"user":{"id":1,"role":"user"}}"#),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html>ok</html>"),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    assert_expected_mass_assignment_payload(&requests, "/users", 1);
}

#[tokio::test]
async fn json_body_with_non_json_content_type_is_still_processed() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"user":{"id":1,"name":"baseline"}}"#),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_string(
                    r#"{"ok":true,"is_admin":true,"role":"admin","permissions":["*"]}"#,
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "mass_assignment/reflected-fields"),
        "expected reflected finding with valid JSON body despite non-json content-type, got: {findings:#?}"
    );
}

#[tokio::test]
async fn post_5xx_response_returns_no_finding() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(500).set_body_string(r#"{"error":"boom"}"#))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    assert_expected_mass_assignment_payload(&requests, "/users", 1);
}

#[tokio::test]
async fn confirmation_get_failure_keeps_reflected_finding() {
    let server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_for_get = Arc::clone(&call_count);

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(move |_request: &wiremock::Request| {
            let call = call_count_for_get.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"user":{"id":1,"role":"user"}}"#)
            } else {
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"user":{"id":1,"role":"admin"}}"#)
            }
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"ok":true,"role":"admin"}"#),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config_with_timeout(true, 1));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(
        findings
            .iter()
            .any(|f| f.check == "mass_assignment/reflected-fields"),
        "expected reflected finding despite confirm GET failure, got: {findings:#?}"
    );
    let reflected = findings
        .iter()
        .find(|f| f.check == "mass_assignment/reflected-fields")
        .expect("expected reflected finding");
    assert!(
        reflected
            .evidence
            .as_deref()
            .unwrap_or("")
            .contains("Confirmation GET failed"),
        "expected reflected finding evidence to mention failed confirmation, got: {reflected:#?}"
    );
    assert!(!errors.is_empty(), "expected timeout/error on confirm GET");
    assert!(
        errors.iter().any(|e| {
            e.context == "http::send"
                && e.message
                    .to_ascii_lowercase()
                    .contains("error sending request")
        }),
        "expected transport error on confirm GET timeout path, got: {errors:#?}"
    );
    assert_expected_mass_assignment_payload(&requests, "/users", 1);
}

#[tokio::test]
async fn mixed_and_camel_case_reflected_fields_are_detected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(
                    r#"{"Is_Admin":true,"isAdmin":true,"Role":"admin","Permissions":["*"]}"#,
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "mass_assignment/reflected-fields"),
        "expected mixed/camel-case reflected finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn empty_post_body_is_ignored() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(""),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
}

#[tokio::test]
async fn empty_json_object_post_is_ignored() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{}"#),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
}

#[tokio::test]
async fn reflected_fields_without_persisted_state_change_stay_medium() {
    let server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_for_get = Arc::clone(&call_count);

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(move |_request: &wiremock::Request| {
            call_count_for_get.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"user":{"id":1,"name":"stable-user"}}"#)
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(
                    r#"{"ok":true,"is_admin":true,"role":"admin","permissions":["*"]}"#,
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "mass_assignment/reflected-fields"),
        "expected medium reflected finding, got: {findings:#?}"
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.check == "mass_assignment/persisted-state-change"),
        "did not expect persisted-state-change for stable confirm GET: {findings:#?}"
    );
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "expected baseline + confirm GET calls"
    );
}

#[tokio::test]
async fn baseline_get_failure_still_reports_reflected_fields() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(2))
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"user":{"id":1}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"ok":true,"role":"admin"}"#),
        )
        .expect(1)
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config_with_timeout(true, 1));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(
        findings
            .iter()
            .any(|f| f.check == "mass_assignment/reflected-fields"),
        "expected reflected finding when baseline GET fails, got: {findings:#?}"
    );
    assert!(
        errors.iter().any(|e| {
            e.context == "http::send"
                && e.message
                    .to_ascii_lowercase()
                    .contains("error sending request")
        }),
        "expected baseline GET transport error, got: {errors:#?}"
    );
    assert_expected_mass_assignment_payload(&requests, "/users", 1);
}

#[tokio::test]
async fn dry_run_reports_info_and_sends_no_requests() {
    let server = MockServer::start().await;

    let cfg = Arc::new(test_config_custom(true, true, 5));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert_finding_exists(&findings, "mass_assignment/dry-run", Severity::Info);
    assert!(
        requests.is_empty(),
        "expected dry-run to avoid network probes, got: {requests:#?}"
    );
}

#[tokio::test]
async fn nested_elevated_fields_confirm_high_severity() {
    let server = MockServer::start().await;

    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_for_get = Arc::clone(&call_count);

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(move |_request: &wiremock::Request| {
            let call = call_count_for_get.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(r#"{"profile":{"meta":{"role":"user"}}}"#)
            } else {
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(
                        r#"{"profile":{"meta":{"role":"admin","permissions":["*"],"is_admin":true}}}"#,
                    )
            }
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(
                    r#"{"result":{"is_admin":true,"role":"admin","permissions":["*"]}}"#,
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "mass_assignment/persisted-state-change"),
        "expected high severity nested-field confirmation, got: {findings:#?}"
    );
}

#[tokio::test]
async fn baseline_sensitive_keys_are_adapted_into_probe_payload() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(
                    r#"{"user":{"id":1,"accountType":"user","is_owner":false,"accessLevel":"viewer","entitlements":["read"]}}"#,
                ),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(
                    r#"{"ok":true,"accountType":"admin","is_owner":true,"accessLevel":"admin","entitlements":["*"]}"#,
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (_findings, _errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    let post = requests
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path() == "/users")
        .expect("expected POST /users request");

    let body: serde_json::Value = serde_json::from_slice(&post.body).expect("json probe payload");
    assert_eq!(body.get("accountType"), Some(&json!("admin")));
    assert_eq!(body.get("is_owner"), Some(&json!(true)));
    assert_eq!(body.get("accessLevel"), Some(&json!("admin")));
    assert_eq!(body.get("entitlements"), Some(&json!(["*"])));
}

#[tokio::test]
async fn more_than_three_newly_elevated_fields_are_all_confirmed() {
    let server = MockServer::start().await;

    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_for_get = Arc::clone(&call_count);

    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(move |_request: &wiremock::Request| {
            let call = call_count_for_get.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(
                        r#"{"user":{"accountType":"user","is_owner":false,"accessLevel":"viewer","entitlements":["read"]}}"#,
                    )
            } else {
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(
                        r#"{"user":{"accountType":"admin","is_owner":true,"accessLevel":"admin","entitlements":["*"]}}"#,
                    )
            }
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(
                    r#"{"ok":true,"accountType":"admin","is_owner":true,"accessLevel":"admin","entitlements":["*"]}"#,
                ),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    let finding = findings
        .iter()
        .find(|f| f.check == "mass_assignment/persisted-state-change")
        .expect("expected persisted-state-change finding");
    let evidence = finding.evidence.as_deref().unwrap_or("");
    assert!(evidence.contains("accounttype"), "evidence: {evidence}");
    assert!(evidence.contains("isowner"), "evidence: {evidence}");
    assert!(evidence.contains("accesslevel"), "evidence: {evidence}");
    assert!(evidence.contains("entitlements"), "evidence: {evidence}");
}

#[tokio::test]
async fn non_mutation_paths_are_skipped() {
    let server = MockServer::start().await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/health", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.is_empty());
}

#[tokio::test]
async fn disabled_active_checks_means_noop() {
    let server = MockServer::start().await;

    let cfg = Arc::new(test_config(false));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = MassAssignmentScanner::new(cfg.as_ref());

    let target = format!("{}/users", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.is_empty());
}
