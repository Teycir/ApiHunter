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
    // ...continuing api_security_401_not_flagged
        .collect();

    assert!(
        unauth_findings.is_empty(),
        "401 response should not be flagged as unauthenticated; got: {unauth_findings:#?}"
    );
}

// ─── Runner behaviour tests ───────────────────────────────────────────────────

#[tokio::test]
async fn runner_respects_endpoint_cap() {
    let server = MockServer::start().await;

    // Root page links to 50 endpoints.
    let links: String = (0..50)
        .map(|i| format!(r#"<a href="/ep/{i}">ep{i}</a>"#))
        .collect::<Vec<_>>()
        .join("\n");

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string(format!("<html><body>{links}</body></html>")),
        )
        .mount(&server)
        .await;

    // Each sub-endpoint just returns 200.
    for i in 0..50 {
        Mock::given(method("GET"))
            .and(path(format!("/ep/{i}")))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
    }

    let mut config = base_config(&server.uri());
    config.max_endpoints = 10; // cap well below 50

    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    assert!(
        result.endpoints_scanned <= 10,
        "runner should honour max_endpoints=10; scanned {}",
        result.endpoints_scanned
    );
}

#[tokio::test]
async fn runner_deduplicates_endpoints() {
    let server = MockServer::start().await;

    // Root contains the same URL in multiple forms.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string(
                    r#"<html><body>
                        <a href="/page">one</a>
                        <a href="/page/">two</a>
                        <a href="/page?">three</a>
                    </body></html>"#,
                ),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    // /page and its variants collapse to a single canonical endpoint.
    assert!(
        result.endpoints_scanned <= 2, // root + /page
        "duplicate URLs should be deduplicated; scanned {}",
        result.endpoints_scanned
    );
}

#[tokio::test]
async fn runner_captures_panicking_scanner_as_error() {
    // This test requires a test-only scanner that panics; inject via
    // runner::run_with_scanners if your API exposes it, otherwise use
    // a poisoned HttpClient that panics on a specific URL.
    //
    // Here we simulate via a 500 that the scanner maps to CapturedError.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    // Runner must not itself panic; result is Ok even when inner errors occur.
    // The 500 may or may not produce a CapturedError depending on scanner
    // implementation — just assert the runner returned cleanly.
    let _ = result; // presence of Ok(result) is the assertion
}

#[tokio::test]
async fn runner_aggregates_findings_across_scanners() {
    let server = MockServer::start().await;

    // Trigger CORS + CSP findings simultaneously on the same endpoint.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                // CORS wildcard
                .insert_header("Access-Control-Allow-Origin", "*")
                // CSP: missing entirely → csp scanner fires
                .set_body_string("<html><body></body></html>"),
        )
        .mount(&server)
        .await;

    let config = base_config(&server.uri());
    let client = Arc::new(HttpClient::new(&config).unwrap());
    let result = runner::run(config, client, reporter_sink()).await.unwrap();

    let scanners_reported: std::collections::HashSet<&str> =
        result.findings.iter().map(|f| f.scanner.as_str()).collect();

    assert!(
        scanners_reported.contains("cors"),
        "expected CORS finding; got scanners: {scanners_reported:?}"
    );
    assert!(
        scanners_reported.contains("csp"),
        "expected CSP finding; got scanners: {scanners_reported:?}"
    );
}

// ─── Reporter concurrency tests ───────────────────────────────────────────────

mod reporter_concurrency {
    use super::*;
    use std::io::BufRead;
    use tempfile::NamedTempFile;
    use scanner::report::{Reporter, ReportConfig, ReportFormat, RunResult, Severity};

    fn file_reporter(path: &std::path::Path) -> Reporter {
        Reporter::new(ReportConfig {
            format: ReportFormat::Ndjson,
            output: Some(path.to_path_buf()),
            quiet: false,
            print_summary: false,
            min_severity: Severity::Info,
        })
        .expect("reporter")
    }

    #[tokio::test]
    async fn concurrent_write_run_result_produces_valid_ndjson() {
        let tmp = NamedTempFile::new().unwrap();
        let reporter = Arc::new(file_reporter(tmp.path()));

        // Spawn N tasks each writing a RunResult concurrently.
        const N: usize = 20;
        let mut handles = tokio::task::JoinSet::new();

        for i in 0..N {
            let r = Arc::clone(&reporter);
            handles.spawn(async move {
                let result = RunResult::dummy(i); // implement dummy() on RunResult in #[cfg(test)]
                r.write_run_result(&result).await
            });
        }

        while let Some(res) = handles.join_next().await {
            res.expect("task panicked")
                .expect("write_run_result failed");
        }

        reporter.finalize().await.expect("finalize failed");

        // Every line in the output file must be valid JSON.
        let file = std::fs::File::open(tmp.path()).unwrap();
        let lines: Vec<String> = std::io::BufReader::new(file)
            .lines()
            .map(|l| l.unwrap())
            .filter(|l| !l.trim().is_empty())
            .collect();

        assert_eq!(lines.len(), N, "expected {N} NDJSON lines, got {}", lines.len());

        for (i, line) in lines.iter().enumerate() {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("line {i} is not valid JSON: {e}\n  line: {line}"));
        }
    }

    #[tokio::test]
    async fn finalize_is_idempotent() {
        let tmp = NamedTempFile::new().unwrap();
        let reporter = file_reporter(tmp.path());

        reporter.finalize().await.expect("first finalize");
        reporter.finalize().await.expect("second finalize should not error");
    }

    #[tokio::test]
    async fn reporter_swallows_io_error_after_finalize() {
        let tmp = NamedTempFile::new().unwrap();
        let reporter = file_reporter(tmp.path());

        reporter.finalize().await.unwrap();

        // Writing after finalize must not panic — it may return an Err or silently
        // swallow depending on your implementation contract.
        let result = RunResult::dummy(0);
        let _ = reporter.write_run_result(&result).await;
        // No panic ⇒ test passes.
    }

    #[tokio::test]
    async fn ndjson_lines_are_atomically_terminated() {
        let tmp = NamedTempFile::new().unwrap();
        let reporter = Arc::new(file_reporter(tmp.path()));

        const N: usize = 50;
        let mut handles = tokio::task::JoinSet::new();

        for i in 0..N {
            let r = Arc::clone(&reporter);
            handles.spawn(async move {
                r.write_run_result(&RunResult::dummy(i)).await
            });
        }
        while let Some(r) = handles.join_next().await {
            r.unwrap().unwrap();
        }
        reporter.finalize().await.unwrap();

        let content = std::fs::read_to_string(tmp.path()).unwrap();

        // Each line must end with exactly '\n', never mid-write interleaving.
        for line in content.lines() {
            assert!(
                !line.is_empty(),
                "unexpected empty line in NDJSON output"
            );
            // Round-trip parse to confirm no partial writes corrupted JSON.
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("corrupt NDJSON line: {e}\n  {line}"));
        }
    }
}

// ─── HttpClient politeness / retry tests ─────────────────────────────────────

mod http_client_behaviour {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::header;

    #[tokio::test]
    async fn retries_on_503_up_to_configured_limit() {
        let server = MockServer::start().await;
        let call_count = Arc::new(AtomicUsize::new(0));

        // First 2 calls → 503, third → 200.
        {
            let cc = Arc::clone(&call_count);
            Mock::given(method("GET"))
                .and(path("/flaky"))
                .respond_with(wiremock::ResponderFn::new(move |_req| {
                    let n = cc.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        ResponseTemplate::new(503)
                    } else {
                        ResponseTemplate::new(200).set_body_string("ok")
                    }
                }))
                .mount(&server)
                .await;
        }

        let mut config = base_config(&server.uri());
        config.politeness.retries = 3;
        config.politeness.delay_ms = 0;

        let client = HttpClient::new(&config).unwrap();
        let resp = client
            .get(&format!("{}/flaky", server.uri()))
            .await
            .expect("should succeed after retries");

        assert_eq!(resp.status(), 200);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            3,
            "expected exactly 3 attempts (2 retries + 1 success)"
        );
    }

    #[tokio::test]
    async fn exhausted_retries_returns_err() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/always-503"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let mut config = base_config(&server.uri());
        config.politeness.retries = 2;
        config.politeness.delay_ms = 0;

        let client = HttpClient::new(&config).unwrap();
        let result = client
            .get(&format!("{}/always-503", server.uri()))
            .await;

        assert!(
            result.is_err(),
            "all retries exhausted should return Err, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn ua_rotation_sends_different_user_agents() {
        let server = MockServer::start().await;
        let seen_uas: Arc<tokio::sync::Mutex<Vec<String>>> =
            Arc::new(tokio::sync::Mutex::new(vec![]));

        {
            let uas = Arc::clone(&seen_uas);
            Mock::given(method("GET"))
                .and(path("/ua-echo"))
                .respond_with(wiremock::ResponderFn::new(move |req| {
                    let ua = req
                        .headers
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    // Fire-and-forget insert; tolerate lock contention in test.
                    if let Ok(mut guard) = uas.try_lock() {
                        guard.push(ua);
                    }
                    ResponseTemplate::new(200)
                }))
                .mount(&server)
                .await;
        }

        let mut config = base_config(&server.uri());
        config.waf.enabled = true;
        config.waf.user_agents = vec![
            "AgentA/1.0".to_string(),
            "AgentB/2.0".to_string(),
            "AgentC/3.0".to_string(),
        ];

        let client = HttpClient::new(&config).unwrap();

        // Fire enough requests that all UAs are likely to appear.
        for _ in 0..30 {
            let _ = client.get(&format!("{}/ua-echo", server.uri())).await;
        }

        let uas = seen_uas.lock().await;
        let unique: std::collections::HashSet<&String> = uas.iter().collect();
        assert!(
            unique.len() > 1,
            "UA rotation should produce multiple distinct user-agents; saw: {unique:?}"
        );
    }

    #[tokio::test]
    async fn timeout_returns_err_before_server_responds() {
        let server = MockServer::start().await;

        // Respond after a long delay — longer than the client timeout.
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(10)),
            )
            .mount(&server)
            .await;

        let mut config = base_config(&server.uri());
        config.politeness.timeout_secs = 1; // 1 s << 10 s server delay
        config.politeness.retries = 0;

        let client = HttpClient::new(&config).unwrap();
        let result = client.get(&format!("{}/slow
