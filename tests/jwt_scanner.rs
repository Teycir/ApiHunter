// tests/jwt_scanner.rs

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::jwt::JwtScanner,
    scanner::Scanner,
};

// Build a minimal Config suitable for tests.
fn test_config() -> Config {
    Config {
        max_endpoints: 100,
        concurrency: 4,
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
        toggles: ScannerToggles {
            cors: true,
            csp: true,
            graphql: true,
            api_security: true,
            jwt: true,
        },
    }
}

type HmacSha256 = Hmac<Sha256>;

fn make_hs256_jwt(secret: &str) -> String {
    let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
    let payload = serde_json::json!({"sub": "123", "exp": 1893456000});

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    format!("{signing_input}.{sig_b64}")
}

#[tokio::test]
async fn jwt_weak_secret_detected() {
    let server = MockServer::start().await;
    let token = make_hs256_jwt("secret");

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "token={token}"
        )))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = JwtScanner::new(cfg.as_ref());

    let (findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(errors.is_empty());
    assert!(findings.iter().any(|f| f.check == "jwt/weak-secret"));
}
