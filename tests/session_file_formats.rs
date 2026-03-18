// tests/session_file_formats.rs
//
// Session file format parsing tests (native vs excalibur).

use std::sync::Arc;

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, SessionFileFormat, WafEvasionConfig},
    http_client::HttpClient,
};
use tempfile::NamedTempFile;
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
        session_file_format: SessionFileFormat::Auto,
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
async fn excalibur_format_option_loads_cookie_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let host = url::Url::parse(&server.uri())
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");
    let cookie_doc = serde_json::json!({
        "cookies": {
            format!(".{host}"): {
                "sid": "abc123",
                "theme": "dark"
            }
        }
    });

    let session_file = NamedTempFile::new().unwrap();
    std::fs::write(
        session_file.path(),
        serde_json::to_vec(&cookie_doc).unwrap(),
    )
    .unwrap();

    let mut cfg = test_config();
    cfg.session_file = Some(session_file.path().to_path_buf());
    cfg.session_file_format = SessionFileFormat::Excalibur;

    let config = Arc::new(cfg);
    let client = HttpClient::new(config.as_ref()).expect("http client");
    let _ = client.get(&server.uri()).await.expect("request");

    let requests = server.received_requests().await.expect("requests");
    let cookie = requests[0]
        .headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(cookie.contains("sid=abc123"));
    assert!(cookie.contains("theme=dark"));
}

#[tokio::test]
async fn auto_format_detects_excalibur_schema() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let host = url::Url::parse(&server.uri())
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");
    let cookie_doc = serde_json::json!({
        "cookies": {
            format!(".{host}"): {
                "sid": "auto-detected"
            }
        }
    });

    let session_file = NamedTempFile::new().unwrap();
    std::fs::write(
        session_file.path(),
        serde_json::to_vec(&cookie_doc).unwrap(),
    )
    .unwrap();

    let mut cfg = test_config();
    cfg.session_file = Some(session_file.path().to_path_buf());
    cfg.session_file_format = SessionFileFormat::Auto;

    let config = Arc::new(cfg);
    let client = HttpClient::new(config.as_ref()).expect("http client");
    let _ = client.get(&server.uri()).await.expect("request");

    let requests = server.received_requests().await.expect("requests");
    let cookie = requests[0]
        .headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(cookie.contains("sid=auto-detected"));
}

#[test]
fn explicit_native_format_rejects_excalibur_schema() {
    let cookie_doc = serde_json::json!({
        "cookies": {
            ".example.com": { "sid": "abc123" }
        }
    });

    let session_file = NamedTempFile::new().unwrap();
    std::fs::write(
        session_file.path(),
        serde_json::to_vec(&cookie_doc).unwrap(),
    )
    .unwrap();

    let mut cfg = test_config();
    cfg.session_file = Some(session_file.path().to_path_buf());
    cfg.session_file_format = SessionFileFormat::Native;

    let err = match HttpClient::new(&cfg) {
        Ok(_) => panic!("native format should reject excalibur schema"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("native"),
        "expected native parse failure, got: {msg}"
    );
}
