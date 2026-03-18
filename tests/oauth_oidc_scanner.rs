use std::sync::Arc;

use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::oauth_oidc::OAuthOidcScanner,
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
        },
        quiet: false,
    }
}

#[tokio::test]
async fn oauth_redirect_uri_probe_detects_untrusted_callback() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .and(query_param("redirect_uri", "https://evil.example/callback"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            "https://evil.example/callback?code=abc&state=ah_state_probe_7f3a",
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{
                    "issuer": "https://issuer.example",
                    "code_challenge_methods_supported": ["S256"],
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"]
                }"#,
        ))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = OAuthOidcScanner::new(cfg.as_ref());

    let target = format!("{}/oauth/authorize", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "oauth/redirect-uri-not-validated"),
        "expected redirect_uri finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn oidc_metadata_flags_pkce_and_legacy_grants() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{
                    "issuer": "https://issuer.example",
                    "code_challenge_methods_supported": ["plain"],
                    "response_types_supported": ["code", "id_token token"],
                    "grant_types_supported": ["authorization_code", "password"]
                }"#,
        ))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = OAuthOidcScanner::new(cfg.as_ref());

    let target = format!("{}/oauth/token", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "oauth/pkce-s256-not-supported"),
        "expected pkce s256 finding, got: {findings:#?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.check == "oauth/implicit-flow-enabled"),
        "expected implicit flow finding, got: {findings:#?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.check == "oauth/ropc-grant-enabled"),
        "expected password grant finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn scanner_noop_when_active_checks_disabled() {
    let server = MockServer::start().await;

    let cfg = Arc::new(test_config(false));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = OAuthOidcScanner::new(cfg.as_ref());

    let target = format!("{}/oauth/authorize", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.is_empty());
}
