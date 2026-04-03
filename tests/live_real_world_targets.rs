use std::{fs, path::Path, sync::Arc, time::Duration};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::{ReportConfig, ReportFormat, Reporter},
    runner,
};

const DEFAULT_TARGET_FILE: &str = "targets/real-world-integration-public.txt";
const ENV_TARGET_FILE: &str = "APIHUNTER_LIVE_REAL_TARGET_FILE";
const ENV_TARGETS_CSV: &str = "APIHUNTER_LIVE_REAL_TARGETS";
const ENV_ENABLE_ACTIVE: &str = "APIHUNTER_LIVE_REAL_ENABLE_ACTIVE";
const ENV_ENABLE_WEBSOCKET: &str = "APIHUNTER_LIVE_REAL_ENABLE_WEBSOCKET";
const MAX_LIVE_TARGETS: usize = 10;
const PER_TARGET_TIMEOUT_SECS: u64 = 45;

fn active_mode_enabled() -> bool {
    std::env::var(ENV_ENABLE_ACTIVE)
        .ok()
        .map(|raw| {
            let v = raw.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false)
}

fn websocket_mode_enabled() -> bool {
    std::env::var(ENV_ENABLE_WEBSOCKET)
        .ok()
        .map(|raw| {
            let v = raw.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false)
}

fn live_config(enable_active: bool, enable_websocket: bool) -> Config {
    Config {
        max_endpoints: 10,
        concurrency: 2,
        politeness: PolitenessConfig {
            delay_ms: 50,
            retries: 1,
            timeout_secs: 8,
        },
        waf_evasion: WafEvasionConfig {
            enabled: false,
            user_agents: vec![],
        },
        default_headers: vec![],
        cookies: vec![],
        proxy: None,
        danger_accept_invalid_certs: false,
        active_checks: enable_active,
        dry_run: true,
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
        no_discovery: true,
        toggles: ScannerToggles {
            cors: true,
            csp: true,
            graphql: true,
            api_security: true,
            jwt: true,
            openapi: true,
            api_versioning: false,
            grpc_protobuf: false,
            mass_assignment: true,
            oauth_oidc: true,
            rate_limit: false,
            cve_templates: false,
            websocket: enable_websocket,
        },
        quiet: true,
    }
}

fn silent_reporter() -> Arc<Reporter> {
    Arc::new(
        Reporter::new(ReportConfig {
            format: ReportFormat::Pretty,
            output_path: None,
            print_summary: false,
            quiet: true,
            stream: false,
        })
        .expect("reporter"),
    )
}

fn load_live_targets() -> Vec<String> {
    if let Ok(csv) = std::env::var(ENV_TARGETS_CSV) {
        let parsed = csv
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !parsed.is_empty() {
            return parsed.into_iter().take(MAX_LIVE_TARGETS).collect();
        }
    }

    let path = std::env::var(ENV_TARGET_FILE).unwrap_or_else(|_| DEFAULT_TARGET_FILE.to_string());
    let path_ref = Path::new(&path);
    let body = fs::read_to_string(path_ref)
        .unwrap_or_else(|e| panic!("failed to read targets file {}: {e}", path_ref.display()));

    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .take(MAX_LIVE_TARGETS)
        .collect::<Vec<_>>()
}

#[tokio::test]
#[ignore = "manual real-world internet integration smoke test"]
async fn live_real_world_targets_smoke() {
    let targets = load_live_targets();
    assert!(
        !targets.is_empty(),
        "no targets loaded; set {ENV_TARGETS_CSV} or {ENV_TARGET_FILE}"
    );

    let enable_active = active_mode_enabled();
    let enable_websocket = websocket_mode_enabled();
    let config = Arc::new(live_config(enable_active, enable_websocket));
    let client = Arc::new(HttpClient::new(config.as_ref()).expect("http client"));
    let reporter = silent_reporter();

    let mut completed_targets = 0usize;
    let mut timed_out_targets = 0usize;
    let mut total_scanned = 0usize;
    let mut targets_with_findings = 0usize;
    let mut targets_without_errors = 0usize;
    let mut aggregate_findings = 0usize;
    let mut aggregate_errors = 0usize;
    let mut summaries = Vec::new();

    for target in &targets {
        let run_result = tokio::time::timeout(
            Duration::from_secs(PER_TARGET_TIMEOUT_SECS),
            runner::run(
                vec![target.clone()],
                Arc::clone(&config),
                Arc::clone(&client),
                None,
                Arc::clone(&reporter),
                true,
            ),
        )
        .await;

        let result = match run_result {
            Ok(result) => {
                completed_targets += 1;
                result
            }
            Err(_) => {
                timed_out_targets += 1;
                aggregate_errors += 1;
                summaries.push(format!(
                    "- {} | scanned=0 findings=0 errors=timeout({}s)",
                    target, PER_TARGET_TIMEOUT_SECS
                ));
                continue;
            }
        };

        let scanned = result.scanned;
        let finding_count = result.findings.len();
        let error_count = result.errors.len();

        total_scanned += scanned;
        aggregate_findings += finding_count;
        aggregate_errors += error_count;
        if finding_count > 0 {
            targets_with_findings += 1;
        }
        if error_count == 0 {
            targets_without_errors += 1;
        }

        summaries.push(format!(
            "- {} | scanned={} findings={} errors={}",
            target, scanned, finding_count, error_count
        ));
    }

    for line in &summaries {
        println!("{line}");
    }
    println!(
        "real-world integration summary: targets={} completed={} timed_out={} scanned={} findings={} errors={} targets_with_findings={} targets_without_errors={} active_mode={} websocket_mode={}",
        targets.len(),
        completed_targets,
        timed_out_targets,
        total_scanned,
        aggregate_findings,
        aggregate_errors,
        targets_with_findings,
        targets_without_errors,
        enable_active,
        enable_websocket
    );

    assert!(
        completed_targets > 0,
        "expected at least one completed target run.\n{}",
        summaries.join("\n")
    );
    assert_eq!(
        completed_targets + timed_out_targets,
        targets.len(),
        "expected completed + timed_out targets to match input.\n{}",
        summaries.join("\n")
    );
    assert_eq!(
        total_scanned,
        completed_targets,
        "expected one scanned URL per completed target.\n{}",
        summaries.join("\n")
    );
    assert!(
        targets_without_errors > 0,
        "expected at least one real-world target to complete without scanner errors.\n{}",
        summaries.join("\n")
    );
}
