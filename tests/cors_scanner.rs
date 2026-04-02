// tests/cors_scanner.rs

use std::sync::Arc;
use std::time::Duration;

use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::cors::CorsScanner,
    scanner::Scanner,
};

fn test_config() -> Config {
    test_config_with_timeout(5)
}

fn test_config_with_timeout(timeout_secs: u64) -> Config {
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
            cors: true,
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

#[tokio::test]
async fn regex_bypass_probe_failures_are_collected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(|request: &wiremock::Request| {
            let origin = request
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if origin.contains(".cdn-edge.net") {
                ResponseTemplate::new(200).set_delay(Duration::from_secs(2))
            } else {
                ResponseTemplate::new(200)
                    .insert_header("Access-Control-Allow-Origin", origin)
                    .insert_header("Access-Control-Allow-Credentials", "true")
            }
        })
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config_with_timeout(1));
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = CorsScanner::new(cfg.as_ref());

    let (_findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(
        !errors.is_empty(),
        "expected timeout errors from regex bypass probes"
    );
    assert!(
        errors.iter().any(|e| e
            .message
            .to_ascii_lowercase()
            .contains("error sending request")),
        "expected network/send error details for bypass probe failures, got: {errors:#?}"
    );
}

#[tokio::test]
async fn options_probe_is_preferred_over_get_when_cors_headers_present() {
    let server = MockServer::start().await;

    Mock::given(method("OPTIONS"))
        .respond_with(|request: &wiremock::Request| {
            let origin = request
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("https://cdn.example.net")
                .to_string();
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", origin)
                .insert_header("Access-Control-Allow-Credentials", "true")
        })
        .mount(&server)
        .await;

    // If scanner falls back to GET despite valid OPTIONS CORS headers, this
    // delay will trigger timeout errors under the short test timeout.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config_with_timeout(1));
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = CorsScanner::new(cfg.as_ref());

    let (_findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;
    assert!(
        errors.is_empty(),
        "OPTIONS-based probing should avoid fallback GET timeout errors, got: {errors:#?}"
    );
}
