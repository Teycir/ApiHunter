use std::collections::HashMap;

use api_scanner::auth::{execute_flow, AuthFlow, AuthStep, InjectAs};
use api_scanner::config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig};
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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
async fn execute_flow_accepts_float_expires_in() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-123",
            "expires_in": 3600.0
        })))
        .mount(&server)
        .await;

    let flow = AuthFlow {
        steps: vec![AuthStep {
            url: format!("{}/login", server.uri()),
            method: "POST".to_string(),
            body: None,
            headers: HashMap::new(),
            extract: Some("$.access_token".to_string()),
            extract_refresh: None,
            extract_expires_in: Some("$.expires_in".to_string()),
            inject_as: Some(InjectAs::Bearer),
        }],
        refresh_interval_secs: 840,
    };

    let cred = execute_flow(&flow, &test_config())
        .await
        .expect("flow with float expires_in should succeed");

    assert_eq!(cred.current(), "token-123");
    assert_eq!(
        cred.refresh_lead_secs, 3540,
        "float expires_in should be normalized to integer seconds and use lead offset",
    );
}

#[tokio::test]
async fn execute_flow_substitutes_lowercase_env_placeholders() {
    let _guard = ENV_LOCK.lock().await;
    let previous = std::env::var("api_key").ok();
    std::env::set_var("api_key", "lower-secret");

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/login"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
            let ok = body.get("api_key").and_then(|v| v.as_str()) == Some("lower-secret");
            if ok {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "token-lowercase"
                }))
            } else {
                ResponseTemplate::new(401).set_body_string("bad credentials")
            }
        })
        .mount(&server)
        .await;

    let flow = AuthFlow {
        steps: vec![AuthStep {
            url: format!("{}/login", server.uri()),
            method: "POST".to_string(),
            body: Some(serde_json::json!({
                "api_key": "{{api_key}}"
            })),
            headers: HashMap::new(),
            extract: Some("$.access_token".to_string()),
            extract_refresh: None,
            extract_expires_in: None,
            inject_as: Some(InjectAs::Bearer),
        }],
        refresh_interval_secs: 840,
    };

    let result = execute_flow(&flow, &test_config()).await;

    if let Some(value) = previous {
        std::env::set_var("api_key", value);
    } else {
        std::env::remove_var("api_key");
    }

    let cred = result.expect("lowercase env placeholders should be substituted");
    assert_eq!(cred.current(), "token-lowercase");
}
