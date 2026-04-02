use std::sync::Arc;

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::{openapi::OpenApiScanner, Scanner},
};
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn test_config() -> Config {
    Config {
        max_endpoints: 10,
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
        active_checks: true,
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
            openapi: true,
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
async fn schema_fuzzing_reports_suspicious_variant_behavior() {
    let server = MockServer::start().await;

    let spec = serde_json::json!({
        "openapi": "3.0.1",
        "info": { "title": "test", "version": "1.0.0" },
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {
                                        "name": { "type": "string" },
                                        "age": { "type": "integer" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/openapi.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(spec))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .and(body_string_contains("apihunter' OR '1'='1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("SQL syntax error near name"))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(201).set_body_string("{\"ok\":true}"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = OpenApiScanner::new(cfg.as_ref());

    let (findings, _errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "openapi/schema-fuzzing-suspected"),
        "expected schema fuzzing finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn race_probe_flags_duplicate_successes_on_sensitive_operation() {
    let server = MockServer::start().await;

    let spec = serde_json::json!({
        "openapi": "3.0.1",
        "info": { "title": "test", "version": "1.0.0" },
        "paths": {
            "/payments/transfer": {
                "post": {
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["amount"],
                                    "properties": {
                                        "amount": { "type": "number" },
                                        "recipient": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/openapi.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(spec))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/payments/transfer"))
        .respond_with(ResponseTemplate::new(201).set_body_string("{\"accepted\":true}"))
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = OpenApiScanner::new(cfg.as_ref());

    let (findings, _errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "openapi/race-probe-possible-idempotency-gap"),
        "expected race-probe finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn oast_probe_is_dispatched_when_oast_env_is_set() {
    let server = MockServer::start().await;

    let spec = serde_json::json!({
        "openapi": "3.0.1",
        "info": { "title": "test", "version": "1.0.0" },
        "paths": {
            "/webhooks/register": {
                "post": {
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["callback_url"],
                                    "properties": {
                                        "callback_url": { "type": "string", "format": "uri" },
                                        "event": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/openapi.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(spec))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/webhooks/register"))
        .respond_with(ResponseTemplate::new(202).set_body_string("{\"queued\":true}"))
        .mount(&server)
        .await;

    let previous = std::env::var("APIHUNTER_OAST_BASE").ok();
    std::env::set_var("APIHUNTER_OAST_BASE", "https://oast.example.test");

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = OpenApiScanner::new(cfg.as_ref());

    let (findings, _errors) = scanner.scan(&server.uri(), &client, cfg.as_ref()).await;

    if let Some(value) = previous {
        std::env::set_var("APIHUNTER_OAST_BASE", value);
    } else {
        std::env::remove_var("APIHUNTER_OAST_BASE");
    }

    let oast_finding = findings
        .iter()
        .find(|finding| finding.check == "openapi/oast-probe-dispatched");

    assert!(
        oast_finding.is_some(),
        "expected OAST probe finding, got: {findings:#?}"
    );
    assert!(
        oast_finding
            .and_then(|finding| finding.evidence.as_ref())
            .map(|evidence| evidence.contains("oast.example.test"))
            .unwrap_or(false),
        "expected OAST evidence to include callback domain"
    );
}
