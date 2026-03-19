use std::collections::HashMap;

use api_scanner::auth::{execute_flow, AuthFlow, AuthStep, InjectAs};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

    let cred = execute_flow(&flow)
        .await
        .expect("flow with float expires_in should succeed");

    assert_eq!(cred.current(), "token-123");
    assert_eq!(
        cred.refresh_lead_secs, 3540,
        "float expires_in should be normalized to integer seconds and use lead offset",
    );
}
