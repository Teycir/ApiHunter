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

fn make_rs256_jwt_with_jwk() -> String {
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        // Minimal RSA JWK; `n` decodes to 65537 bytes [0x01, 0x00, 0x01]
        "jwk": { "kty": "RSA", "n": "AQAB", "e": "AQAB" }
    });
    let payload = serde_json::json!({"sub":"123","exp":1893456000});
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
    let sig_b64 = URL_SAFE_NO_PAD.encode("sig");
    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut n = len;
    while n > 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();
    let mut out = vec![0x80 | (bytes.len() as u8)];
    out.extend(bytes);
    out
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(value.len()));
    out.extend_from_slice(value);
    out
}

fn der_integer(raw: &[u8]) -> Vec<u8> {
    let mut v = raw.to_vec();
    while v.len() > 1 && v.first() == Some(&0) {
        v.remove(0);
    }
    if v.is_empty() {
        v.push(0);
    }
    if (v[0] & 0x80) != 0 {
        v.insert(0, 0);
    }
    der_tlv(0x02, &v)
}

fn build_rsa_spki_der_for_test(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut pkcs1 = Vec::new();
    pkcs1.extend(der_integer(modulus));
    pkcs1.extend(der_integer(exponent));
    let rsa_pkcs1 = der_tlv(0x30, &pkcs1);

    let alg_id_value = vec![
        0x06, 0x09, // OBJECT IDENTIFIER len
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // rsaEncryption
        0x05, 0x00, // NULL
    ];
    let alg_id = der_tlv(0x30, &alg_id_value);

    let mut bit_string = vec![0x00];
    bit_string.extend(rsa_pkcs1);
    let subject_public_key = der_tlv(0x03, &bit_string);

    let mut spki_value = Vec::new();
    spki_value.extend(alg_id);
    spki_value.extend(subject_public_key);
    der_tlv(0x30, &spki_value)
}

fn verify_hs256_bearer_token(auth: &str, secret: &[u8]) -> bool {
    let token = match auth.strip_prefix("Bearer ") {
        Some(t) => t,
        None => return false,
    };
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    let header = match URL_SAFE_NO_PAD.decode(parts[0].as_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let header_json: serde_json::Value = match serde_json::from_slice(&header) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if header_json.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
        return false;
    }

    let sig = match URL_SAFE_NO_PAD.decode(parts[2].as_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig).is_ok()
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
    let token = make_rs256_jwt_with_jwk();
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

#[tokio::test]
async fn alg_confusion_detected_when_forged_hs256_matches_jwk_spki() {
    let server = MockServer::start().await;

    let modulus = vec![0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44];
    let exponent = vec![0x01, 0x00, 0x01];
    let jwk_n = URL_SAFE_NO_PAD.encode(&modulus);
    let jwk_e = URL_SAFE_NO_PAD.encode(&exponent);
    let token_header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "jwk": { "kty": "RSA", "n": jwk_n, "e": jwk_e }
    });
    let token_payload = serde_json::json!({"sub":"123","exp":1893456000});
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(token_header.to_string()),
        URL_SAFE_NO_PAD.encode(token_payload.to_string()),
        URL_SAFE_NO_PAD.encode("sig")
    );

    let expected_secret = build_rsa_spki_der_for_test(&modulus, &exponent);
    let expected_secret_for_server = expected_secret.clone();
    let token_for_server = token.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_server = Arc::clone(&calls);

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(move |request: &wiremock::Request| {
            let call = calls_for_server.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return ResponseTemplate::new(200)
                    .set_body_string(format!("token={token_for_server}"));
            }

            let auth = request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if verify_hs256_bearer_token(auth, &expected_secret_for_server) {
                ResponseTemplate::new(200).set_body_string("accepted")
            } else {
                ResponseTemplate::new(401)
            }
        })
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config_custom(true, 5));
    let client = HttpClient::new(cfg.as_ref()).unwrap();
    let scanner = JwtScanner::new(cfg.as_ref());

    let (findings, errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(
        errors.is_empty(),
        "expected no transport/probe errors for true-positive path, got: {errors:#?}"
    );
    assert!(
        findings.iter().any(|f| f.check == "jwt/alg-confusion"),
        "expected jwt/alg-confusion finding, got: {findings:#?}"
    );
}
