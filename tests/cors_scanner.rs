// tests/cors_scanner.rs

use std::sync::Arc;

use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, SessionFileFormat, WafEvasionConfig},
    http_client::HttpClient,
    scanner::cors::CorsScanner,
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
        active_checks: false,
        stream_findings: false,
        baseline_path: None,
        session_file: None,
        session_file_format: SessionFileFormat::Auto,
        auth_bearer: None,
        auth_basic: None,
        auth_flow: None,
        auth_flow_b: None,
        unauth_strip_headers: vec![],
        per_host_clients: false,
        adaptive_concurrency: false,
        toggles: ScannerToggles {
            cors: true,
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
async fn wildcard_with_credentials_is_skipped() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "*")
                .insert_header("Access-Control-Allow-Credentials", "true"),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = CorsScanner::new(cfg.as_ref());

    let (findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.is_empty());
}

#[tokio::test]
async fn same_origin_reflection_not_reported() {
    let server = MockServer::start().await;
    let origin = server.uri();

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", origin.as_str())
                .insert_header("Access-Control-Allow-Credentials", "true"),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = CorsScanner::new(cfg.as_ref());

    let (findings, errors) = scanner.scan(&origin, &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.is_empty());
}
