// tests/jwt_scanner.rs

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::jwt::JwtScanner,
    scanner::Scanner,
};

// Build a minimal Config suitable for tests.
fn test_config() -> Config {
    test_config_custom(false, 5)
}

fn test_config_custom(active_checks: bool, timeout_secs: u64) -> Config {
    Config {
        max_endpoints: 100,
        concurrency: 4,
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
            csp: true,
            graphql: true,
            api_security: true,
            jwt: true,
            openapi: true,
            mass_assignment: true,
            oauth_oidc: true,
            rate_limit: true,
            cve_templates: true,
            websocket: true,
        },
        quiet: false,
    }
}

type HmacSha256 = Hmac<Sha256>;

fn make_hs256_jwt_with_payload(secret: &str, payload: serde_json::Value) -> String {
    let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    format!("{signing_input}.{sig_b64}")
}

fn make_hs256_jwt(secret: &str) -> String {
    let payload = serde_json::json!({"sub": "123", "exp": 1893456000});
    make_hs256_jwt_with_payload(secret, payload)
}

fn make_rs256_jwt_with_x5c() -> String {
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "x5c": ["QUJD"] // "ABC" base64
    });
    let payload = serde_json::json!({"sub":"123","exp":1893456000});
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
    let sig_b64 = URL_SAFE_NO_PAD.encode("sig");
    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

#[tokio::test]
async fn jwt_weak_secret_detected() {
    let server = MockServer::start().await;
    let token = make_hs256_jwt("secret");

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("token={token}")))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = JwtScanner::new(cfg.as_ref());

    let (findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.iter().any(|f| f.check == "jwt/weak-secret"));
}

#[tokio::test]
async fn jwt_clean_token_no_findings() {
    let server = MockServer::start().await;
    let now = Utc::now().timestamp();
    let payload = serde_json::json!({
        "iss": "https://issuer.example",
        "aud": "api",
        "iat": now,
        "exp": now + 3600
    });
    let token = make_hs256_jwt_with_payload("very-strong-secret-123", payload);

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("token={token}")))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = JwtScanner::new(cfg.as_ref());

    let (findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.is_empty());
}

#[tokio::test]
async fn malformed_jwt_decode_errors_are_reported() {
    let server = MockServer::start().await;
    let payload_b64 = URL_SAFE_NO_PAD.encode(r#"{"sub":"123","exp":1893456000}"#);
    let token = format!("eyJ9.{payload_b64}.c2ln");

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("token={token}")))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = JwtScanner::new(cfg.as_ref());

    let (_findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(
        errors.iter().any(|e| e.context == "jwt/decode"),
        "expected jwt/decode error for malformed JWT segments, got: {errors:#?}"
    );
}

#[tokio::test]
async fn alg_confusion_probe_failure_is_reported() {
    let server = MockServer::start().await;
    let token = make_rs256_jwt_with_x5c();
    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_for_get = Arc::clone(&call_count);

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(move |_request: &wiremock::Request| {
            let call = call_count_for_get.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                ResponseTemplate::new(200).set_body_string(format!("token={token}"))
            } else {
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .set_body_string("slow")
            }
        })
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config_custom(true, 1));
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = JwtScanner::new(cfg.as_ref());

    let (_findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(
        errors
            .iter()
            .any(|e| e.message.contains("alg_confusion_probe")),
        "expected alg_confusion_probe error context, got: {errors:#?}"
    );
}
