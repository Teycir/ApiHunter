use std::sync::Arc;

use api_scanner::auth::{spawn_refresh_task, AuthFlow, InjectAs, LiveCredential};
use api_scanner::config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig};
use arc_swap::ArcSwap;

#[tokio::test]
async fn refresh_task_can_be_cancelled_immediately() {
    let flow = AuthFlow {
        steps: vec![],
        refresh_interval_secs: 3600,
    };
    let cred = Arc::new(LiveCredential {
        value: Arc::new(ArcSwap::from_pointee("token".to_string())),
        refresh_value: None,
        inject_as: InjectAs::Bearer,
        refresh_lead_secs: 3600,
    });

    let config = Config {
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
    };

    let handle = spawn_refresh_task(flow, cred, config);

    let res = tokio::time::timeout(std::time::Duration::from_secs(1), handle.shutdown()).await;
    assert!(res.is_ok(), "refresh task shutdown timed out");
}
