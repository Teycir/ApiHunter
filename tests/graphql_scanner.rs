use std::sync::Arc;

use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::graphql::GraphqlScanner,
    scanner::Scanner,
};

fn test_config() -> Config {
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
        active_checks: true,
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

#[tokio::test]
async fn rest_like_seed_skips_base_url_graphql_probe() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = GraphqlScanner::new(cfg.as_ref());

    let target = format!("{}/v2/users", server.uri());
    let (_findings, _errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(
        !requests.iter().any(|r| r.url.path() == "/v2/users"),
        "did not expect direct probe against REST-like seed path; requests: {requests:#?}"
    );
    assert!(
        requests
            .iter()
            .any(|r| r.url.path().starts_with("/v2/users/")),
        "expected scanner to probe derived GraphQL paths; requests: {requests:#?}"
    );
}

#[tokio::test]
async fn graphql_like_seed_keeps_base_probe() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = GraphqlScanner::new(cfg.as_ref());

    let target = format!("{}/api/graphql", server.uri());
    let (_findings, _errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let requests = server.received_requests().await.expect("received requests");

    assert!(
        requests.iter().any(|r| r.url.path() == "/api/graphql"),
        "expected base GraphQL path probe; requests: {requests:#?}"
    );
}

#[tokio::test]
async fn mutation_fuzzing_reports_accepted_mutation_payloads() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_string_contains("__schema"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "__schema": { "types": [] } }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_string_contains("createUser"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "createUser": { "id": "1" } }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "errors": [{ "message": "blocked" }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = GraphqlScanner::new(cfg.as_ref());

    let target = format!("{}/graphql", server.uri());
    let (findings, _errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "graphql/mutation-fuzzing-accepted"),
        "expected mutation fuzzing accepted finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn mutation_fuzzing_dry_run_emits_plan_without_mutation_requests() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_string_contains("__schema"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "__schema": { "types": [] } }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "errors": [{ "message": "ignored" }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let mut cfg = test_config();
    cfg.dry_run = true;
    let cfg = Arc::new(cfg);
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = GraphqlScanner::new(cfg.as_ref());

    let target = format!("{}/graphql", server.uri());
    let (findings, _errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "graphql/mutation-fuzzing-dry-run"),
        "expected dry-run mutation fuzzing finding, got: {findings:#?}"
    );

    let requests = server.received_requests().await.expect("received requests");
    assert!(
        !requests.iter().any(|request| {
            request
                .body
                .windows("createUser".len())
                .any(|window| window == b"createUser")
        }),
        "did not expect actual mutation payload execution in dry-run mode"
    );
}
