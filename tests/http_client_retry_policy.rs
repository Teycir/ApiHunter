use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

fn test_config() -> Config {
    Config {
        max_endpoints: 10,
        concurrency: 2,
        politeness: PolitenessConfig {
            delay_ms: 0,
            retries: 2,
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
            api_versioning: false,
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
async fn retries_503_responses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/retryable"))
        .respond_with(ResponseTemplate::new(503))
        .expect(3)
        .mount(&server)
        .await;

    let cfg = test_config();
    let client = HttpClient::new(&cfg).expect("http client");
    let resp = client
        .get(&format!("{}/retryable", server.uri()))
        .await
        .expect("request");

    assert_eq!(resp.status, 503);
    let metrics = client.runtime_metrics();
    assert_eq!(metrics.requests_sent, 3);
    assert_eq!(metrics.retries_performed, 2);
}

#[tokio::test]
async fn does_not_retry_501_responses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/not-implemented"))
        .respond_with(ResponseTemplate::new(501))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = test_config();
    let client = HttpClient::new(&cfg).expect("http client");
    let resp = client
        .get(&format!("{}/not-implemented", server.uri()))
        .await
        .expect("request");

    assert_eq!(resp.status, 501);
    let metrics = client.runtime_metrics();
    assert_eq!(metrics.requests_sent, 1);
    assert_eq!(metrics.retries_performed, 0);
}
