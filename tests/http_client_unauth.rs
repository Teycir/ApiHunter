// tests/http_client_unauth.rs
//
// Ensure unauthenticated probes do not send auth-like headers.

use std::sync::Arc;

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
};
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

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
        active_checks: false,
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
async fn unauthenticated_probe_strips_auth_headers() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut cfg = test_config();
    cfg.default_headers = vec![
        ("Authorization".to_string(), "Bearer secret".to_string()),
        ("X-API-Key".to_string(), "api-key-123".to_string()),
        ("X-Custom-Auth".to_string(), "custom-456".to_string()),
    ];
    cfg.cookies = vec![("session".to_string(), "abc123".to_string())];
    cfg.unauth_strip_headers = vec!["X-Custom-Auth".to_string()];

    let config = Arc::new(cfg);
    let client = HttpClient::new(&config).expect("http client");

    let url = format!("{}/private/42", server.uri());
    let _ = client.get_without_auth(&url).await.expect("request");

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1, "expected exactly one request");
    let headers = &requests[0].headers;

    assert!(headers.get("authorization").is_none());
    assert!(headers.get("cookie").is_none());
    assert!(headers.get("x-api-key").is_none());
    assert!(headers.get("x-custom-auth").is_none());
}
