// tests/integration_runner.rs
//
// Round-trip integration tests: spin up a real HTTP mock server (wiremock),
// build a genuine Config + HttpClient, call runner::run(), and assert on the
// returned findings / errors.
//
// Cargo.toml dev-dependencies needed:
//   wiremock      = "0.6"
//   tokio         = { version = "1", features = ["full", "test-util"] }
//   tempfile      = "3"
//   assert_matches = "1"

use std::sync::Arc;
use assert_matches::assert_matches;
use wiremock::{
    matchers::{method, path, header_exists},
    Mock, MockServer, ResponseTemplate,
};

use scanner::{
    config::{
        Config, PolitenessConfig, ScannerToggles, WafEvasionConfig,
    },
    http_client::HttpClient,
    report::{Reporter, ReportConfig, ReportFormat, Severity},
    runner,
};

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal Config pointing at a wiremock base URL.
fn base_config(base_url: &str) -> Config {
    Config {
        max_endpoints: 100,
        concurrency: 4,
        politeness: PolitenessConfig {
            delay_ms: 0,       // no artificial delay in tests
            retries: 0,        // fail fast; individual tests opt-in to retries
            timeout_secs: 5,
        },
        toggles: ScannerToggles {
            cors: true,
            csp: true,
            graphql: true,
            api_security: true,
        },
        waf: WafEvasionConfig {
            enabled: false,
            user_agents: vec![],
        },
        proxy: None,
        danger_accept_invalid_certs: false,
        seed_urls: vec![base_url.to_string()],
    }
}

fn reporter_sink() -> Reporter {
    // Write to /dev/null; we only care about the returned RunResult.
    Reporter::new(ReportConfig {
        format: ReportFormat::Ndjson,
        output: None, // stdout sink – swallowed by test harness
        quiet: true,
        print_summary: false,
        min_severity: Severity::Info,
    })
    .expect("reporter")
}

// ─── CORS tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn cors_wildcard_origin_detected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "*")
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    // Reflection probe
    Mock::given(method("GET"))
        .and(path("/"))
        .and(header_exists("Origin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "*")
                .insert_header("Access-Control-Allow-Credentials", "true"),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let reporter = reporter_sink();

    let result = runner::run(config, client, reporter).await.unwrap();

    let cors_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.scanner == "cors")
        .collect();

    assert!(
        !cors_findings.is_empty(),
        "expected at least one CORS finding; got: {:#?}",
        result.findings
    );
}

#[tokio::test]
async fn cors_null_origin_reflected_is_high_or_critical() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "null")
                .insert_header("Access-Control-Allow-Credentials", "true")
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"ok":true}"#),
        )
        .mount(&server)
        .await;

    // Make discovery see /api/data by embedding it in the root page.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string(
                    r#"<html><body><a href="/api/data">data</a></body></html>"#,
                ),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let high_cors = result.findings.iter().any(|f| {
        f.scanner == "cors"
            && matches!(f.severity, Severity::High | Severity::Critical)
    });
    assert!(high_cors, "null-origin+credentials should be High/Critical");
}

#[tokio::test]
async fn cors_same_origin_no_finding() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    // No CORS headers → no finding expected.
    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let cors_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.scanner == "cors")
        .collect();

    assert!(
        cors_findings.is_empty(),
        "same-origin should produce no CORS findings; got: {cors_findings:#?}"
    );
}

// ─── CSP tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn csp_missing_header_detected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let has_csp_missing = result
        .findings
        .iter()
        .any(|f| f.scanner == "csp" && f.title.to_lowercase().contains("missing"));

    assert!(has_csp_missing, "missing CSP header should be reported");
}

#[tokio::test]
async fn csp_unsafe_inline_detected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .insert_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'unsafe-inline'",
                )
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let has_unsafe = result.findings.iter().any(|f| {
        f.scanner == "csp" && f.title.to_lowercase().contains("unsafe-inline")
    });
    assert!(has_unsafe, "'unsafe-inline' in CSP should be flagged");
}

#[tokio::test]
async fn csp_strict_policy_no_finding() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .insert_header(
                    "Content-Security-Policy",
                    "default-src 'none'; script-src 'self'; object-src 'none'",
                )
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let csp_findings: Vec<_> =
        result.findings.iter().filter(|f| f.scanner == "csp").collect();

    assert!(
        csp_findings.is_empty(),
        "strict CSP should produce no findings; got: {csp_findings:#?}"
    );
}

// ─── GraphQL tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn graphql_introspection_enabled_detected() {
    let server = MockServer::start().await;

    // Discovery root
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string(
                    r#"<html><body><a href="/graphql">API</a></body></html>"#,
                ),
        )
        .mount(&server)
        .await;

    // Introspection probe
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(
                    r#"{"data":{"__schema":{"types":[{"name":"Query"}]}}}"#,
                ),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let has_introspection = result.findings.iter().any(|f| {
        f.scanner == "graphql" && f.title.to_lowercase().contains("introspection")
    });
    assert!(has_introspection, "open introspection should be reported");
}

#[tokio::test]
async fn graphql_introspection_disabled_no_finding() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string(
                    r#"<html><body><a href="/graphql">API</a></body></html>"#,
                ),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"errors":[{"message":"Introspection disabled"}]}"#),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let introspection_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.scanner == "graphql" && f.title.to_lowercase().contains("introspection"))
        .collect();

    assert!(
        introspection_findings.is_empty(),
        "disabled introspection should not be flagged; got: {introspection_findings:#?}"
    );
}

// ─── API security tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn api_security_unauth_endpoint_detected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string(
                    r#"<html><body><a href="/api/users">users</a></body></html>"#,
                ),
        )
        .mount(&server)
        .await;

    // Returns 200 with no auth required → misconfiguration
    Mock::given(method("GET"))
        .and(path("/api/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"[{"id":1,"email":"admin@example.com"}]"#),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let api_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.scanner == "api_security")
        .collect();

    assert!(
        !api_findings.is_empty(),
        "unauthenticated API endpoint should be flagged"
    );
}

#[tokio::test]
async fn api_security_401_not_flagged() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string(
                    r#"<html><body><a href="/api/admin">admin</a></body></html>"#,
                ),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/admin"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("WWW-Authenticate", "Bearer")
                .set_body_string(r#"{"error":"unauthorized"}"#),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let unauth_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.scanner == "api_security"
                && f.title.to_lowercase().contains("unauthenticated")
        })
        .collect
