use std::sync::Arc;

use wiremock::matchers::{method, path};
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
            cve_templates: false,
            websocket: false,
        },
        quiet: false,
    }
}

#[tokio::test]
async fn oauth_redirect_uri_probe_detects_untrusted_callback() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(|request: &wiremock::Request| {
            let mut redirect_uri = None;
            let mut state = None;
            for (k, v) in request.url.query_pairs() {
                if k == "redirect_uri" {
                    redirect_uri = Some(v.into_owned());
                } else if k == "state" {
                    state = Some(v.into_owned());
                }
            }

            let location = format!(
                "{}?code=abc&state={}",
                redirect_uri.unwrap_or_else(|| "https://app.example.net/callback".to_string()),
                state.unwrap_or_else(|| "missing".to_string())
            );
            ResponseTemplate::new(302).insert_header("Location", location)
        })
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
async fn authorize_probe_uses_configured_auth_headers_and_cookies() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(|request: &wiremock::Request| {
            let auth_ok = request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                == Some("Bearer keepme");
            let cookie_ok = request
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("session=abc123"))
                .unwrap_or(false);

            if !(auth_ok && cookie_ok) {
                return ResponseTemplate::new(401).set_body_string("login required");
            }

            let mut redirect_uri = None;
            let mut state = None;
            for (k, v) in request.url.query_pairs() {
                if k == "redirect_uri" {
                    redirect_uri = Some(v.into_owned());
                } else if k == "state" {
                    state = Some(v.into_owned());
                }
            }

            let location = format!(
                "{}?code=abc&state={}",
                redirect_uri.unwrap_or_else(|| "https://app.example.net/callback".to_string()),
                state.unwrap_or_else(|| "missing".to_string())
            );
            ResponseTemplate::new(302).insert_header("Location", location)
        })
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

    let mut cfg = test_config(true);
    cfg.default_headers = vec![("Authorization".to_string(), "Bearer keepme".to_string())];
    cfg.cookies = vec![("session".to_string(), "abc123".to_string())];
    let cfg = Arc::new(cfg);
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = OAuthOidcScanner::new(cfg.as_ref());

    let target = format!("{}/oauth/authorize", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|f| f.check == "oauth/redirect-uri-not-validated"),
        "expected redirect_uri finding when authorized probe is used, got: {findings:#?}"
    );

    let metrics = client.runtime_metrics();
    assert_eq!(
        metrics.requests_sent, 2,
        "expected authorize probe + metadata probe to be counted in runtime metrics"
    );
}

#[tokio::test]
async fn state_not_returned_is_reported_even_without_redirect_uri_acceptance() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "https://trusted-idp.example/callback?code=abc"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(404))
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
            .any(|f| f.check == "oauth/state-not-returned"),
        "expected state-not-returned finding, got: {findings:#?}"
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.check == "oauth/redirect-uri-not-validated"),
        "did not expect redirect-uri-not-validated for trusted location, got: {findings:#?}"
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
    let requests = server.received_requests().await.expect("received requests");

    assert!(
        requests
            .iter()
            .any(|r| r.url.path() == "/.well-known/openid-configuration"),
        "expected metadata request to be sent, got requests: {requests:#?}"
    );

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

#[tokio::test]
async fn metadata_parse_error_includes_metadata_url_context() {
    let server = MockServer::start().await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = OAuthOidcScanner::new(cfg.as_ref());

    let expected_metadata_url = format!("{}/.well-known/openid-configuration", server.uri());
    client.cache_spec(&expected_metadata_url, "{invalid-json");

    let target = format!("{}/oauth/token", server.uri());
    let (_findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;
    let parse_error = errors
        .iter()
        .find(|e| e.context == "oauth/openid-metadata-parse")
        .unwrap_or_else(|| panic!("expected openid metadata parse error, got: {errors:#?}"));
    assert_eq!(
        parse_error.url.as_deref(),
        Some(expected_metadata_url.as_str()),
        "expected metadata parse error to include failing metadata URL context"
    );
}
