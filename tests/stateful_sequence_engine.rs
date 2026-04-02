use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::common::sequence::{SequenceActor, SequenceRunner, SequenceStep},
};
use reqwest::Method;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
        no_discovery: true,
        toggles: ScannerToggles {
            cors: false,
            csp: false,
            graphql: false,
            api_security: false,
            jwt: false,
            openapi: false,
            api_versioning: false,
            mass_assignment: false,
            oauth_oidc: false,
            rate_limit: false,
            cve_templates: false,
            websocket: false,
        },
        quiet: true,
    }
}

#[tokio::test]
async fn sequence_runner_executes_actor_matrix_steps() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/matrix"))
        .and(header("authorization", "Bearer primary"))
        .respond_with(ResponseTemplate::new(200).set_body_string("primary"))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/matrix"))
        .and(header("authorization", "Bearer secondary"))
        .respond_with(ResponseTemplate::new(200).set_body_string("secondary"))
        .mount(&server)
        .await;

    let mut cfg_primary = test_config();
    cfg_primary.default_headers = vec![("Authorization".to_string(), "Bearer primary".to_string())];
    let client_primary = HttpClient::new(&cfg_primary).expect("primary client");

    let mut cfg_secondary = cfg_primary.clone();
    cfg_secondary.default_headers =
        vec![("Authorization".to_string(), "Bearer secondary".to_string())];
    let client_secondary = HttpClient::new(&cfg_secondary).expect("secondary client");

    let url = format!("{}/matrix", server.uri());
    let steps = vec![
        SequenceStep::new("primary", SequenceActor::Primary, Method::GET, &url),
        SequenceStep::new("unauth", SequenceActor::Unauthenticated, Method::GET, &url),
        SequenceStep::new("secondary", SequenceActor::Secondary, Method::GET, &url),
    ];

    let (results, errors) = SequenceRunner::new(&client_primary, Some(&client_secondary))
        .run(&steps)
        .await;

    assert!(errors.is_empty(), "unexpected sequence errors: {errors:#?}");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].status, Some(200));
    assert_eq!(results[1].status, Some(404));
    assert_eq!(results[2].status, Some(200));
}

#[tokio::test]
async fn sequence_runner_reports_invalid_unauthenticated_post() {
    let server = MockServer::start().await;
    let cfg = test_config();
    let client = HttpClient::new(&cfg).expect("client");

    let url = format!("{}/unsupported", server.uri());
    let steps = vec![SequenceStep::new(
        "unauth-post",
        SequenceActor::Unauthenticated,
        Method::POST,
        &url,
    )
    .with_json_body(serde_json::json!({"x": 1}))];

    let (results, errors) = SequenceRunner::new(&client, None).run(&steps).await;

    assert_eq!(results.len(), 1);
    assert!(results[0].status.is_none());
    assert!(
        errors
            .iter()
            .any(|e| e.context == "sequence/unauthenticated-method"),
        "expected unauthenticated method error, got: {errors:#?}"
    );
}
