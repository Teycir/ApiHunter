#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    collections::{BTreeMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use api_scanner::{
    config::{Config, PolitenessConfig, ScannerToggles, WafEvasionConfig},
    http_client::HttpClient,
    reports::{self, Finding, ReportConfig, ReportFormat, Reporter, Severity},
    runner::{self, ProgressEvent},
};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};

static NEXT_SCAN_ID: AtomicU64 = AtomicU64::new(1);
const MAX_TARGETS: usize = 100;

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    status: String,
    app_version: String,
    scanner_version: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanToggleRequest {
    cors: bool,
    csp: bool,
    graphql: bool,
    api_security: bool,
    jwt: bool,
    openapi: bool,
    #[serde(default = "default_true")]
    api_versioning: bool,
    #[serde(default = "default_true")]
    grpc_protobuf: bool,
    mass_assignment: bool,
    oauth_oidc: bool,
    rate_limit: bool,
    cve_templates: bool,
    websocket: bool,
}

impl Default for ScanToggleRequest {
    fn default() -> Self {
        Self {
            cors: true,
            csp: true,
            graphql: true,
            api_security: true,
            jwt: true,
            openapi: true,
            api_versioning: true,
            grpc_protobuf: true,
            mass_assignment: true,
            oauth_oidc: true,
            rate_limit: true,
            cve_templates: true,
            websocket: true,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct FullScanRequest {
    target_url: Option<String>,
    target_urls: Option<Vec<String>>,
    active_checks: bool,
    dry_run: bool,
    #[serde(default)]
    response_diff_deep: bool,
    no_discovery: bool,
    no_filter: bool,
    filter_timeout: u64,
    max_endpoints: usize,
    concurrency: usize,
    timeout_secs: u64,
    retries: u32,
    delay_ms: u64,
    waf_evasion: bool,
    user_agents: Vec<String>,
    headers: Vec<String>,
    cookies: Vec<String>,
    proxy: Option<String>,
    danger_accept_invalid_certs: bool,
    auth_bearer: Option<String>,
    auth_basic: Option<String>,
    unauth_strip_headers: Vec<String>,
    per_host_clients: bool,
    adaptive_concurrency: bool,
    toggles: ScanToggleRequest,
}

impl FullScanRequest {
    fn quick(target_url: String) -> Self {
        Self {
            target_url: Some(target_url),
            target_urls: None,
            active_checks: false,
            dry_run: true,
            response_diff_deep: false,
            no_discovery: true,
            no_filter: false,
            filter_timeout: 3,
            max_endpoints: 50,
            concurrency: 4,
            timeout_secs: 15,
            retries: 1,
            delay_ms: 0,
            waf_evasion: false,
            user_agents: Vec::new(),
            headers: Vec::new(),
            cookies: Vec::new(),
            proxy: None,
            danger_accept_invalid_certs: false,
            auth_bearer: None,
            auth_basic: None,
            unauth_strip_headers: Vec::new(),
            per_host_clients: false,
            adaptive_concurrency: false,
            toggles: ScanToggleRequest {
                cors: true,
                csp: true,
                graphql: true,
                api_security: true,
                jwt: true,
                openapi: true,
                api_versioning: true,
                grpc_protobuf: true,
                mass_assignment: false,
                oauth_oidc: false,
                rate_limit: false,
                cve_templates: false,
                websocket: false,
            },
        }
    }

    fn resolve_targets(&self) -> Result<Vec<String>, String> {
        let mut combined = Vec::new();
        if let Some(target_url) = &self.target_url {
            combined.push(target_url.clone());
        }
        if let Some(target_urls) = &self.target_urls {
            combined.extend(target_urls.iter().cloned());
        }

        let mut seen = HashSet::new();
        let mut normalized = Vec::new();
        for target in combined {
            let trimmed = target.trim();
            if trimmed.is_empty() {
                continue;
            }
            if seen.insert(trimmed.to_string()) {
                normalized.push(trimmed.to_string());
            }
        }

        if normalized.is_empty() {
            return Err("Add at least one target URL.".to_string());
        }
        if normalized.len() > MAX_TARGETS {
            return Err(format!(
                "A maximum of {MAX_TARGETS} targets is allowed per scan (received {}).",
                normalized.len()
            ));
        }

        Ok(normalized)
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TopCheck {
    check: String,
    count: usize,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanSummary {
    target: String,
    scanned: usize,
    skipped: usize,
    findings_total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    errors: usize,
    elapsed_ms: u128,
    top_checks: Vec<TopCheck>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanExports {
    pretty_json: String,
    ndjson: String,
    sarif: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FullScanResponse {
    scan_id: u64,
    summary: ScanSummary,
    exports: ScanExports,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveExportRequest {
    file_name: String,
    content: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveExportResponse {
    path: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanEventPayload {
    scan_id: u64,
    event: String,
    message: String,
    total_urls: Option<usize>,
    completed_urls: Option<usize>,
    url: Option<String>,
    findings: Option<usize>,
    critical: Option<usize>,
    high: Option<usize>,
    medium: Option<usize>,
    errors: Option<usize>,
    elapsed_ms: Option<u128>,
}

#[derive(Debug, Serialize)]
struct SarifReport {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "fullDescription")]
    full_description: SarifText,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<SarifText>,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifText,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
struct SarifText {
    text: String,
}

#[tauri::command]
fn health_check() -> HealthResponse {
    HealthResponse {
        status: "ok".to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

#[tauri::command]
async fn run_quick_scan(app: tauri::AppHandle, target_url: String) -> Result<ScanSummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        tauri::async_runtime::block_on(run_quick_scan_impl(app, target_url))
    })
    .await
    .map_err(|e| format!("scan worker failed: {e}"))?
}

async fn run_quick_scan_impl(
    app: tauri::AppHandle,
    target_url: String,
) -> Result<ScanSummary, String> {
    let req = FullScanRequest::quick(target_url);
    let response = run_full_scan_impl(app, req).await?;
    Ok(response.summary)
}

#[tauri::command]
async fn run_full_scan(
    app: tauri::AppHandle,
    request: FullScanRequest,
) -> Result<FullScanResponse, String> {
    tauri::async_runtime::spawn_blocking(move || {
        tauri::async_runtime::block_on(run_full_scan_impl(app, request))
    })
    .await
    .map_err(|e| format!("scan worker failed: {e}"))?
}

#[tauri::command]
fn save_export(
    app: tauri::AppHandle,
    request: SaveExportRequest,
) -> Result<SaveExportResponse, String> {
    let file_name = request.file_name.trim();
    if file_name.is_empty() {
        return Err("fileName cannot be empty.".to_string());
    }
    if file_name.contains('/') || file_name.contains('\\') || file_name.contains("..") {
        return Err("fileName contains unsupported path characters.".to_string());
    }

    let base_dir = app
        .path()
        .download_dir()
        .or_else(|_| app.path().home_dir())
        .map_err(|e| format!("cannot resolve output directory: {e}"))?;

    let output_path = base_dir.join(file_name);
    std::fs::write(&output_path, request.content)
        .map_err(|e| format!("failed to save file: {e}"))?;

    Ok(SaveExportResponse {
        path: output_path.to_string_lossy().to_string(),
    })
}

async fn run_full_scan_impl(
    app: tauri::AppHandle,
    request: FullScanRequest,
) -> Result<FullScanResponse, String> {
    let targets = request.resolve_targets()?;

    for (idx, target) in targets.iter().enumerate() {
        let parsed_url = url::Url::parse(target).map_err(|_| {
            format!(
                "Target #{} must be a valid absolute URL (http/https): {}",
                idx + 1,
                target
            )
        })?;
        if !matches!(parsed_url.scheme(), "http" | "https") {
            return Err(format!(
                "Target #{} must use http or https: {}",
                idx + 1,
                target
            ));
        }
    }

    if !request.no_filter && request.filter_timeout == 0 {
        return Err(
            "filterTimeout must be greater than 0 when accessibility filtering is enabled."
                .to_string(),
        );
    }
    if request.concurrency == 0 {
        return Err("concurrency must be greater than 0.".to_string());
    }

    let auth_bearer = normalize_optional_string(request.auth_bearer);
    if let Some(token) = &auth_bearer {
        if token.chars().any(char::is_whitespace) {
            return Err("authBearer must not contain whitespace.".to_string());
        }
    }

    let auth_basic = normalize_optional_string(request.auth_basic);
    if let Some(creds) = &auth_basic {
        let Some((user, pass)) = creds.split_once(':') else {
            return Err("authBasic must use USER:PASS format.".to_string());
        };
        if user.is_empty() || pass.is_empty() {
            return Err("authBasic must include non-empty USER and PASS.".to_string());
        }
    }

    let proxy = normalize_optional_string(request.proxy);
    let headers = parse_default_headers(&request.headers, &auth_bearer, &auth_basic)?;
    let cookies = parse_cookies(&request.cookies)?;
    let user_agents = sanitize_string_list(&request.user_agents);
    let unauth_strip_headers = sanitize_string_list(&request.unauth_strip_headers);
    let max_endpoints = if request.max_endpoints == 0 {
        usize::MAX
    } else {
        request.max_endpoints
    };

    let config = Arc::new(Config {
        max_endpoints,
        concurrency: request.concurrency.max(1),
        politeness: PolitenessConfig {
            delay_ms: request.delay_ms,
            retries: request.retries,
            timeout_secs: request.timeout_secs.max(1),
        },
        waf_evasion: WafEvasionConfig {
            enabled: request.waf_evasion || !user_agents.is_empty(),
            user_agents,
        },
        default_headers: headers,
        cookies,
        proxy,
        danger_accept_invalid_certs: request.danger_accept_invalid_certs,
        active_checks: request.active_checks,
        dry_run: request.dry_run,
        response_diff_deep: request.response_diff_deep,
        stream_findings: false,
        baseline_path: None,
        session_file: None,
        auth_bearer,
        auth_basic,
        auth_flow: None,
        auth_flow_b: None,
        unauth_strip_headers,
        per_host_clients: request.per_host_clients,
        adaptive_concurrency: request.adaptive_concurrency,
        no_discovery: request.no_discovery,
        quiet: true,
        toggles: ScannerToggles {
            cors: request.toggles.cors,
            csp: request.toggles.csp,
            graphql: request.toggles.graphql,
            api_security: request.toggles.api_security,
            jwt: request.toggles.jwt,
            openapi: request.toggles.openapi,
            api_versioning: request.toggles.api_versioning,
            grpc_protobuf: request.toggles.grpc_protobuf,
            mass_assignment: request.toggles.mass_assignment,
            oauth_oidc: request.toggles.oauth_oidc,
            rate_limit: request.toggles.rate_limit,
            cve_templates: request.toggles.cve_templates,
            websocket: request.toggles.websocket,
        },
    });

    let scan_id = NEXT_SCAN_ID.fetch_add(1, Ordering::Relaxed);
    let mut scan_targets = targets;

    if !request.no_filter {
        emit_scan_event(
            &app,
            ScanEventPayload {
                scan_id,
                event: "log".to_string(),
                message: format!(
                    "Filtering {} targets for reachability (timeout: {}s)",
                    scan_targets.len(),
                    request.filter_timeout
                ),
                total_urls: None,
                completed_urls: None,
                url: None,
                findings: None,
                critical: None,
                high: None,
                medium: None,
                errors: None,
                elapsed_ms: None,
            },
        );

        let (accessible, inaccessible) =
            filter_accessible_urls(&scan_targets, config.as_ref(), request.filter_timeout).await;
        if !inaccessible.is_empty() {
            emit_scan_event(
                &app,
                ScanEventPayload {
                    scan_id,
                    event: "log".to_string(),
                    message: format!(
                        "Filtered out {} inaccessible target(s); continuing with {}.",
                        inaccessible.len(),
                        accessible.len()
                    ),
                    total_urls: None,
                    completed_urls: None,
                    url: None,
                    findings: None,
                    critical: None,
                    high: None,
                    medium: None,
                    errors: None,
                    elapsed_ms: None,
                },
            );
        }
        scan_targets = accessible;
    }

    if scan_targets.is_empty() {
        return Err("No accessible targets remain after filtering.".to_string());
    }

    emit_scan_event(
        &app,
        ScanEventPayload {
            scan_id,
            event: "log".to_string(),
            message: format!("Starting scan for {} targets", scan_targets.len()),
            total_urls: None,
            completed_urls: None,
            url: None,
            findings: None,
            critical: None,
            high: None,
            medium: None,
            errors: None,
            elapsed_ms: None,
        },
    );

    let http_client = Arc::new(HttpClient::new(&config).map_err(|e| e.to_string())?);
    let reporter_cfg = ReportConfig {
        format: ReportFormat::Pretty,
        output_path: None,
        print_summary: false,
        quiet: true,
        stream: false,
    };
    let reporter = Arc::new(Reporter::new(reporter_cfg).map_err(|e| e.to_string())?);

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel::<ProgressEvent>();
    let app_for_events = app.clone();
    let progress_task = tauri::async_runtime::spawn(async move {
        let mut completed_urls = 0usize;
        let mut total_urls = 0usize;

        while let Some(event) = progress_rx.recv().await {
            match event {
                ProgressEvent::Started { total_urls: total } => {
                    total_urls = total;
                    emit_scan_event(
                        &app_for_events,
                        ScanEventPayload {
                            scan_id,
                            event: "started".to_string(),
                            message: format!("Scanning {total_urls} URLs"),
                            total_urls: Some(total_urls),
                            completed_urls: Some(completed_urls),
                            url: None,
                            findings: None,
                            critical: None,
                            high: None,
                            medium: None,
                            errors: None,
                            elapsed_ms: None,
                        },
                    );
                }
                ProgressEvent::UrlCompleted {
                    url,
                    findings,
                    critical,
                    high,
                    medium,
                } => {
                    completed_urls = completed_urls.saturating_add(1);
                    let message = if findings == 0 {
                        format!("{url} | clean")
                    } else {
                        format!("{url} | {findings} findings (C:{critical} H:{high} M:{medium})")
                    };
                    emit_scan_event(
                        &app_for_events,
                        ScanEventPayload {
                            scan_id,
                            event: "progress".to_string(),
                            message,
                            total_urls: Some(total_urls),
                            completed_urls: Some(completed_urls),
                            url: Some(url),
                            findings: Some(findings),
                            critical: Some(critical),
                            high: Some(high),
                            medium: Some(medium),
                            errors: None,
                            elapsed_ms: None,
                        },
                    );
                }
                ProgressEvent::Finished {
                    scanned,
                    skipped,
                    findings,
                    errors,
                } => {
                    emit_scan_event(
                        &app_for_events,
                        ScanEventPayload {
                            scan_id,
                            event: "finished_progress".to_string(),
                            message: format!(
                                "Completed: scanned={scanned}, skipped={skipped}, findings={findings}, errors={errors}"
                            ),
                            total_urls: Some(scanned),
                            completed_urls: Some(scanned),
                            url: None,
                            findings: Some(findings),
                            critical: None,
                            high: None,
                            medium: None,
                            errors: Some(errors),
                            elapsed_ms: None,
                        },
                    );
                }
            }
        }
    });

    let progress_tx_for_runner = progress_tx.clone();
    let run_result = runner::run_with_progress(
        scan_targets.clone(),
        Arc::clone(&config),
        http_client,
        None,
        reporter,
        true,
        Some(progress_tx_for_runner),
    )
    .await;

    drop(progress_tx);
    let _ = progress_task.await;

    let summary = summarize_run(&scan_targets, &run_result);
    let exports = build_exports(&run_result)?;

    emit_scan_event(
        &app,
        ScanEventPayload {
            scan_id,
            event: "completed".to_string(),
            message: format!(
                "Scan complete: {} findings, {} errors",
                summary.findings_total, summary.errors
            ),
            total_urls: Some(summary.scanned),
            completed_urls: Some(summary.scanned),
            url: None,
            findings: Some(summary.findings_total),
            critical: Some(summary.critical),
            high: Some(summary.high),
            medium: Some(summary.medium),
            errors: Some(summary.errors),
            elapsed_ms: Some(summary.elapsed_ms),
        },
    );

    Ok(FullScanResponse {
        scan_id,
        summary,
        exports,
    })
}

fn normalize_optional_string(input: Option<String>) -> Option<String> {
    input
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn sanitize_string_list(raws: &[String]) -> Vec<String> {
    raws.iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn parse_default_headers(
    raws: &[String],
    auth_bearer: &Option<String>,
    auth_basic: &Option<String>,
) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();

    for raw in raws {
        let mut parts = raw.splitn(2, ':');
        let name = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if name.is_empty() || value.is_empty() {
            return Err(format!(
                "Invalid header format: '{raw}' (expected NAME:VALUE)."
            ));
        }
        out.push((name.to_string(), value.to_string()));
    }

    let has_auth = out
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("authorization"));

    if !has_auth {
        if let Some(token) = auth_bearer {
            out.push(("Authorization".to_string(), format!("Bearer {token}")));
        } else if let Some(creds) = auth_basic {
            let encoded = BASE64_STANDARD.encode(creds.as_bytes());
            out.push(("Authorization".to_string(), format!("Basic {encoded}")));
        }
    }

    Ok(out)
}

fn parse_cookies(raws: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for raw in raws {
        let mut parts = raw.splitn(2, '=');
        let name = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if name.is_empty() {
            return Err(format!(
                "Invalid cookie format: '{raw}' (expected NAME=VALUE)."
            ));
        }
        out.push((name.to_string(), value.to_string()));
    }
    Ok(out)
}

async fn filter_accessible_urls(
    urls: &[String],
    config: &Config,
    timeout_secs: u64,
) -> (Vec<String>, Vec<String>) {
    let mut filter_config = config.clone();
    filter_config.politeness.timeout_secs = timeout_secs.max(1);
    filter_config.politeness.retries = 0;

    let client = match HttpClient::new(&filter_config) {
        Ok(c) => c,
        Err(_) => return (urls.to_vec(), Vec::new()),
    };

    let mut accessible = Vec::new();
    let mut inaccessible = Vec::new();
    for url in urls {
        if client.get(url).await.is_ok() {
            accessible.push(url.clone());
        } else {
            inaccessible.push(url.clone());
        }
    }

    (accessible, inaccessible)
}

fn summarize_run(targets: &[String], run_result: &runner::RunResult) -> ScanSummary {
    let summary = reports::build_summary(run_result);

    let mut top_checks_map: BTreeMap<String, usize> = BTreeMap::new();
    for finding in &run_result.findings {
        *top_checks_map.entry(finding.check.clone()).or_default() += 1;
    }

    let mut top_checks: Vec<TopCheck> = top_checks_map
        .into_iter()
        .map(|(check, count)| TopCheck { check, count })
        .collect();
    top_checks.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.check.cmp(&b.check)));
    top_checks.truncate(10);

    ScanSummary {
        target: if targets.len() == 1 {
            targets[0].clone()
        } else {
            format!("{} targets", targets.len())
        },
        scanned: run_result.scanned,
        skipped: run_result.skipped,
        findings_total: run_result.findings.len(),
        critical: summary.critical,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
        info: summary.info,
        errors: run_result.errors.len(),
        elapsed_ms: run_result.elapsed.as_millis(),
        top_checks,
    }
}

fn build_exports(run_result: &runner::RunResult) -> Result<ScanExports, String> {
    let doc = reports::build_document(run_result);

    let pretty_json = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;

    let header = serde_json::json!({
        "type": "meta",
        "meta": &doc.meta,
        "summary": &doc.summary,
    });
    let mut lines = vec![serde_json::to_string(&header).map_err(|e| e.to_string())?];

    for finding in &doc.findings {
        lines.push(serde_json::to_string(finding).map_err(|e| e.to_string())?);
    }
    for err in &doc.errors {
        lines.push(serde_json::to_string(err).map_err(|e| e.to_string())?);
    }

    let sarif = build_sarif(&doc.findings)?;

    Ok(ScanExports {
        pretty_json,
        ndjson: lines.join("\n"),
        sarif,
    })
}

fn build_sarif(findings: &[Finding]) -> Result<String, String> {
    let mut rules_map: BTreeMap<String, SarifRule> = BTreeMap::new();
    let mut results = Vec::new();

    for finding in findings {
        rules_map
            .entry(finding.check.clone())
            .or_insert_with(|| SarifRule {
                id: finding.check.clone(),
                name: finding.title.clone(),
                short_description: SarifText {
                    text: finding.title.clone(),
                },
                full_description: SarifText {
                    text: finding.detail.clone(),
                },
                help: finding
                    .remediation
                    .as_ref()
                    .map(|rem| SarifText { text: rem.clone() }),
            });

        let level = match finding.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        };

        let message = if let Some(evidence) = &finding.evidence {
            format!("{} — {}", finding.detail, evidence)
        } else {
            finding.detail.clone()
        };

        results.push(SarifResult {
            rule_id: finding.check.clone(),
            level: level.to_string(),
            message: SarifText { text: message },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: finding.url.clone(),
                    },
                },
            }],
        });
    }

    let report = SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "apihunter-desktop".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    rules: rules_map.into_values().collect(),
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())
}

fn emit_scan_event(app: &tauri::AppHandle, payload: ScanEventPayload) {
    if let Err(err) = app.emit("scan-event", payload) {
        eprintln!("failed to emit scan-event: {err}");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            health_check,
            run_quick_scan,
            run_full_scan,
            save_export
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run();
}
