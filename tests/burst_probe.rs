use std::{sync::Arc, time::Instant};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    scanner::common::probe::BurstProbe,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_config() -> Config {
    Config {
        max_endpoints: 10,
        concurrency: 8,
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
async fn burst_probe_executes_requests_concurrently() {
    let server = MockServer::start().await;
    let count = 8usize;

    Mock::given(method("GET"))
        .and(path("/burst"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(150)))
        .expect(count as u64)
        .mount(&server)
        .await;

    let cfg = Arc::new(test_config());
    let client = HttpClient::new(cfg.as_ref()).expect("http client");
    let probe = BurstProbe::new(count, None);
    let url = format!("{}/burst", server.uri());

    let start = Instant::now();
    let results = probe.execute(&client, &url).await;
    let elapsed = start.elapsed();

    assert_eq!(results.len(), count);
    assert!(
        results
            .iter()
            .all(|r| matches!(r, Ok(resp) if resp.status == 200)),
        "all burst probe requests should succeed: {results:#?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(700),
        "burst probe should run concurrently (elapsed: {elapsed:?})"
    );
}
