use std::sync::Arc;

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::{grpc_protobuf::GrpcProtobufScanner, Scanner},
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

fn test_config(active_checks: bool) -> Config {
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
        active_checks,
        dry_run: false,
        response_diff_deep: false,
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
            api_versioning: false,
            grpc_protobuf: true,
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
async fn detects_grpc_transport_headers() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rpc.user.v1.Users/GetProfile"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/grpc+proto")
                .insert_header("grpc-status", "0"),
        )
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(false));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = GrpcProtobufScanner::new(cfg.as_ref());

    let target = format!("{}/rpc.user.v1.Users/GetProfile", server.uri());
    let (findings, errors) = scanner.scan(&target, &client, cfg.as_ref()).await;

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    assert!(
        findings
            .iter()
            .any(|finding| finding.check == "grpc_protobuf/grpc-transport-detected"),
        "expected grpc transport finding, got: {findings:#?}"
    );
}

#[tokio::test]
async fn active_reflection_probe_runs_once_per_host() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/users"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/orders"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/grpc")
                .insert_header("grpc-status", "12"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config(true));
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let scanner = GrpcProtobufScanner::new(cfg.as_ref());

    let target_a = format!("{}/api/users", server.uri());
    let (findings_a, errors_a) = scanner.scan(&target_a, &client, cfg.as_ref()).await;
    assert!(
        errors_a.is_empty(),
        "unexpected first errors: {errors_a:#?}"
    );
    assert!(
        findings_a
            .iter()
            .any(|finding| finding.check == "grpc_protobuf/grpc-reflection-or-health-surface"),
        "expected grpc reflection finding on first scan, got: {findings_a:#?}"
    );

    let target_b = format!("{}/api/orders", server.uri());
    let (findings_b, errors_b) = scanner.scan(&target_b, &client, cfg.as_ref()).await;
    assert!(
        errors_b.is_empty(),
        "unexpected second errors: {errors_b:#?}"
    );
    assert!(
        findings_b
            .iter()
            .all(|finding| finding.check != "grpc_protobuf/grpc-reflection-or-health-surface"),
        "expected no duplicate grpc reflection finding on second same-host scan"
    );
}
