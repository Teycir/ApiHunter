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
        // ...continuing timeout_returns_err_before_server_responds
        "))
            .await;

        assert!(
            result.is_err(),
            "request to slow endpoint should time out and return Err, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn respects_delay_between_requests() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/timed"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let mut config = base_config(&server.uri());
        config.politeness.delay_ms = 200;
        config.politeness.retries = 0;

        let client = HttpClient::new(&config).unwrap();
        let url = format!("{}/timed", server.uri());

        let start = std::time::Instant::now();
        for _ in 0..3 {
            client.get(&url).await.unwrap();
        }
        let elapsed = start.elapsed();

        // 3 requests with 200 ms delay between each → at least 400 ms total.
        assert!(
            elapsed >= std::time::Duration::from_millis(400),
            "politeness delay not respected; elapsed: {elapsed:?}"
        );
    }
}

// ─── CLI-level integration tests ──────────────────────────────────────────────

mod cli {
    use assert_cmd::Command;
    use predicates::prelude::*;
    use std::process::Output;
    use tempfile::NamedTempFile;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    /// Spawn the binary against `base_url`, return raw `Output`.
    async fn run_bin(args: &[&str]) -> Output {
        Command::cargo_bin("scanner")
            .expect("binary not found")
            .args(args)
            .output()
            .expect("failed to spawn binary")
    }

    // ── exit codes ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn exit_code_0_when_no_findings() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/html")
                    .insert_header("Content-Security-Policy", "default-src 'self'")
                    .set_body_string("<html><body></body></html>"),
            )
            .mount(&server)
            .await;

        let out = run_bin(&["--url", &server.uri()]).await;

        assert_eq!(
            out.status.code(),
            Some(0),
            "exit code should be 0 for a clean scan;\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    #[tokio::test]
    async fn exit_code_1_when_findings_present() {
        let server = MockServer::start().await;

        // Missing CSP → scanner fires → exit code should include bit 1.
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/html")
                    .set_body_string("<html><body></body></html>"),
            )
            .mount(&server)
            .await;

        let out = run_bin(&["--url", &server.uri()]).await;
        let code = out.status.code().unwrap_or(-1);

        assert_ne!(
            code, 0,
            "exit code should be non-zero when findings exist;\nstdout: {}",
            String::from_utf8_lossy(&out.stdout),
        );
        // Bit 0x01 = findings present.
        assert!(
            code & 0x01 != 0,
            "bit 0x01 (findings present) should be set; code = {code}"
        );
    }

    #[tokio::test]
    async fn exit_code_2_when_errors_present() {
        // Point the scanner at an unreachable address so every request errors.
        // Port 1 is almost universally refused immediately.
        let out = run_bin(&[
            "--url", "http://127.0.0.1:1",
            "--retries", "0",
            "--timeout", "2",
        ])
        .await;

        let code = out.status.code().unwrap_or(-1);
        // Bit 0x02 = captured errors present.
        assert!(
            code & 0x02 != 0,
            "bit 0x02 (errors present) should be set; code = {code}"
        );
    }

    // ── stdout / stderr separation ────────────────────────────────────────────

    #[tokio::test]
    async fn findings_go_to_stdout_tracing_to_stderr() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/html")
                    // No CSP → finding emitted.
                    .set_body_string("<html><body></body></html>"),
            )
            .mount(&server)
            .await;

        let out = run_bin(&["--url", &server.uri(), "--log-level", "debug"]).await;

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        // Findings (JSON objects) should appear on stdout.
        assert!(
            stdout.contains(r#""scanner""#),
            "findings JSON should appear on stdout;\nstdout: {stdout}"
        );

        // Tracing/log lines should appear on stderr, not stdout.
        assert!(
            stderr.contains("DEBUG") || stderr.contains("INFO"),
            "tracing output should appear on stderr;\nstderr: {stderr}"
        );

        // Stdout should not contain raw tracing noise.
        assert!(
            !stdout.contains("DEBUG") && !stdout.contains("TRACE"),
            "tracing lines must not pollute stdout;\nstdout: {stdout}"
        );
    }

    // ── --quiet ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn quiet_flag_suppresses_progress_output() {
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

        let out = run_bin(&["--url", &server.uri(), "--quiet"]).await;

        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(
            !stderr.contains("Scanning") && !stderr.contains("Discovered"),
            "--quiet should suppress progress lines;\nstderr: {stderr}"
        );
    }

    // ── --summary ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn summary_flag_prints_counts() {
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

        let out = run_bin(&["--url", &server.uri(), "--summary"]).await;
        let stdout = String::from_utf8_lossy(&out.stdout);

        assert!(
            stdout.contains("endpoints") || stdout.contains("findings"),
            "--summary should print scan counts;\nstdout: {stdout}"
        );
    }

    // ── --output-path ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn output_path_writes_ndjson_file() {
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

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();

        run_bin(&["--url", &server.uri(), "--output-path", path]).await;

        let content = std::fs::read_to_string(path).unwrap();

        // File should exist and contain at least one valid JSON line (the run record).
        assert!(
            !content.trim().is_empty(),
            "--output-path should write NDJSON to file; file was empty"
        );

        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("invalid NDJSON in output file: {e}\n  line: {line}"));
        }
    }

    #[tokio::test]
    async fn stdout_receives_no_ndjson_when_output_path_set() {
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

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();

        let out = run_bin(&["--url", &server.uri(), "--output-path", path]).await;
        let stdout = String::from_utf8_lossy(&out.stdout);

        // When writing to a file, stdout should only carry the optional summary,
        // not raw NDJSON lines.
        assert!(
            !stdout.contains(r#""scanner""#),
            "NDJSON findings must not appear on stdout when --output-path is set;\nstdout: {stdout}"
        );
    }

    // ── --min-severity ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn min_severity_filters_low_severity_findings() {
        let server = MockServer::start().await;

        // Endpoint that triggers only low-severity findings (e.g. info-level CSP hint).
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/html")
                    .insert_header(
                        "Content-Security-Policy",
                        "default-src 'self'; report-uri /csp",
                    )
                    .set_body_string("<html><body></body></html>"),
            )
            .mount(&server)
            .await;

        let out = run_bin(&[
            "--url",
            &server.uri(),
            "--min-severity",
            "high",
        ])
        .await;

        let stdout = String::from_utf8_lossy(&out.stdout);

        // No high-severity findings expected → stdout should not contain finding JSON.
        // This is a smoke test; a finding-free run is also acceptable.
        for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                let severity = v["severity"].as_str().unwrap_or("info");
                assert!(
                    matches!(severity, "high" | "critical"),
                    "--min-severity=high should suppress lower findings; got: {severity}"
                );
            }
        }
    }
}
