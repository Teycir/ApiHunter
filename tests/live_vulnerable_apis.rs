use std::{fs, path::Path, sync::Arc};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::{ReportConfig, ReportFormat, Reporter},
    runner,
};

const DEFAULT_TARGET_FILE: &str = "targets/vuln-api-regression-real-public.txt";
const ENV_TARGET_FILE: &str = "APIHUNTER_LIVE_VULN_TARGET_FILE";
const ENV_TARGETS_CSV: &str = "APIHUNTER_LIVE_VULN_TARGETS";
const MAX_LIVE_TARGETS: usize = 10;

fn live_config() -> Config {
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
        active_checks: true,
        dry_run: true,
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
            cors: false,
            csp: false,
            graphql: false,
            api_security: true,
            jwt: false,
            openapi: true,
            mass_assignment: false,
            oauth_oidc: false,
            rate_limit: false,
            cve_templates: false,
            websocket: false,
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
#[ignore = "manual live validation against intentionally vulnerable APIs"]
async fn live_vulnerable_targets_emit_findings() {
    let targets = load_live_targets();
    assert!(
        !targets.is_empty(),
        "no targets loaded; set {ENV_TARGETS_CSV} or {ENV_TARGET_FILE}"
    );

    let config = Arc::new(live_config());
    let client = Arc::new(HttpClient::new(config.as_ref()).expect("http client"));
    let reporter = silent_reporter();

    let mut targets_with_findings = 0usize;
    let mut aggregate_findings = 0usize;
    let mut summaries = Vec::new();

    for target in targets {
        let result = runner::run(
            vec![target.clone()],
            Arc::clone(&config),
            Arc::clone(&client),
            None,
            Arc::clone(&reporter),
            true,
        )
        .await;

        let finding_count = result.findings.len();
        let error_count = result.errors.len();
        let top_checks = result
            .findings
            .iter()
            .take(3)
            .map(|finding| finding.check.clone())
            .collect::<Vec<_>>();

        if finding_count > 0 {
            targets_with_findings += 1;
            aggregate_findings += finding_count;
        }

        summaries.push(format!(
            "- {} | findings={} errors={} checks={}",
            target,
            finding_count,
            error_count,
            top_checks.join(",")
        ));
    }

    for line in &summaries {
        println!("{line}");
    }
    println!(
        "live validation summary: targets_with_findings={} aggregate_findings={}",
        targets_with_findings, aggregate_findings
    );

    assert!(
        targets_with_findings > 0,
        "expected at least one intentionally vulnerable target to emit findings.\n{}",
        summaries.join("\n")
    );
    assert!(
        aggregate_findings > 0,
        "expected aggregate findings > 0.\n{}",
        summaries.join("\n")
    );
}
