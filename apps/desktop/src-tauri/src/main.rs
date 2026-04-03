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
    reports::{
        self, CapturedErrorRecord, Finding, ReportConfig, ReportFormat, ReportSummary, Reporter,
        Severity,
    },
    runner::{self, ProgressEvent},
};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};

static NEXT_SCAN_ID: AtomicU64 = AtomicU64::new(1);
static OAST_ENV_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));
const MAX_TARGETS: usize = 100;
const OAST_BASE_ENV: &str = "APIHUNTER_OAST_BASE";

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
    oast_base: Option<String>,
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
            oast_base: None,
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
    insomnia_collection_json: String,
    insomnia_runner_data_json: String,
    per_target_json: Vec<TargetJsonExport>,
    target_summaries: Vec<TargetDiscoverySummary>,
    discovery_ranking: Vec<TargetDiscoveryRank>,
    target_summary_json: String,
    discovery_ranking_json: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TargetJsonExport {
    target: String,
    file_name: String,
    pretty_json: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TargetDiscoverySummary {
    target: String,
    discoveries: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    errors: usize,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TargetDiscoveryRank {
    rank: usize,
    target: String,
    discoveries: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetExportOverview {
    generated_at: String,
    targets: usize,
    total_discoveries: usize,
    unscoped_errors: usize,
    summaries: Vec<TargetDiscoverySummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetRankingOverview {
    generated_at: String,
    targets: usize,
    ranking: Vec<TargetDiscoveryRank>,
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
    folder_name: Option<String>,
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

#[derive(Debug, Serialize)]
struct PostmanCollection {
    info: PostmanCollectionInfo,
    item: Vec<PostmanItem>,
}

#[derive(Debug, Serialize)]
struct PostmanCollectionInfo {
    name: String,
    schema: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct PostmanItem {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    item: Option<Vec<PostmanItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<PostmanRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    response: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct PostmanRequest {
    method: String,
    header: Vec<PostmanHeader>,
    url: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct PostmanHeader {
    key: String,
    value: String,
    #[serde(rename = "type")]
    kind: String,
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
    let file_name = validate_path_component(&request.file_name, "fileName")?;

    let base_dir = app
        .path()
        .download_dir()
        .or_else(|_| app.path().home_dir())
        .map_err(|e| format!("cannot resolve output directory: {e}"))?;

    let folder_name = match request.folder_name {
        Some(name) => validate_path_component(&name, "folderName")?,
        None => default_export_folder_name(),
    };
    let output_dir = base_dir.join(folder_name);
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("failed to create export folder: {e}"))?;

    let output_path = output_dir.join(file_name);
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
    let oast_base = normalize_optional_string(request.oast_base);
    if let Some(base) = &oast_base {
        let parsed = url::Url::parse(base)
            .map_err(|_| "oastBase must be a valid absolute URL.".to_string())?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("oastBase must use http or https.".to_string());
        }
    }
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
    let _oast_lock = OAST_ENV_LOCK.lock().await;
    let _oast_guard = ScopedEnvVar::set(OAST_BASE_ENV, oast_base.as_deref());

    if request.active_checks {
        let message = if let Some(base) = &oast_base {
            format!("Blind SSRF callback correlation enabled: {base}")
        } else {
            "Blind SSRF callback correlation disabled (set OAST callback base to enable)."
                .to_string()
        };
        emit_scan_event(
            &app,
            ScanEventPayload {
                scan_id,
                event: "log".to_string(),
                message,
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
    let exports = build_exports(&scan_targets, &run_result)?;

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

struct ScopedEnvVar {
    key: &'static str,
    previous: Option<String>,
}

impl ScopedEnvVar {
    fn set(key: &'static str, next: Option<&str>) -> Self {
        let previous = std::env::var(key).ok();
        match next {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
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

fn build_exports(
    targets: &[String],
    run_result: &runner::RunResult,
) -> Result<ScanExports, String> {
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
    let insomnia_collection_json = build_insomnia_collection_export(targets, run_result)?;
    let insomnia_runner_data_json = build_insomnia_runner_data_export(targets, run_result)?;
    let (per_target_json, target_summaries, discovery_ranking, unscoped_errors) =
        build_per_target_exports(targets, run_result)?;

    let generated_at = Utc::now().to_rfc3339();
    let total_discoveries = target_summaries
        .iter()
        .fold(0usize, |acc, item| acc.saturating_add(item.discoveries));

    let summary_doc = TargetExportOverview {
        generated_at: generated_at.clone(),
        targets: target_summaries.len(),
        total_discoveries,
        unscoped_errors,
        summaries: target_summaries.clone(),
    };
    let ranking_doc = TargetRankingOverview {
        generated_at,
        targets: discovery_ranking.len(),
        ranking: discovery_ranking.clone(),
    };
    let target_summary_json =
        serde_json::to_string_pretty(&summary_doc).map_err(|e| e.to_string())?;
    let discovery_ranking_json =
        serde_json::to_string_pretty(&ranking_doc).map_err(|e| e.to_string())?;

    Ok(ScanExports {
        pretty_json,
        ndjson: lines.join("\n"),
        sarif,
        insomnia_collection_json,
        insomnia_runner_data_json,
        per_target_json,
        target_summaries,
        discovery_ranking,
        target_summary_json,
        discovery_ranking_json,
    })
}

#[derive(Debug)]
struct TargetMatcher {
    host: String,
    port: Option<u16>,
    path_prefix: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetReportMeta {
    generated_at: String,
    target: String,
    discoveries: usize,
    errors: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetReportDocument {
    meta: TargetReportMeta,
    summary: ReportSummary,
    findings: Vec<Finding>,
    errors: Vec<CapturedErrorRecord>,
}

fn build_per_target_exports(
    targets: &[String],
    run_result: &runner::RunResult,
) -> Result<
    (
        Vec<TargetJsonExport>,
        Vec<TargetDiscoverySummary>,
        Vec<TargetDiscoveryRank>,
        usize,
    ),
    String,
> {
    let matchers = build_target_matchers(targets);
    let mut findings_by_target: Vec<Vec<Finding>> = vec![Vec::new(); targets.len()];
    let mut errors_by_target: Vec<Vec<CapturedErrorRecord>> =
        (0..targets.len()).map(|_| Vec::new()).collect();
    let mut unscoped_errors = 0usize;

    for finding in &run_result.findings {
        if let Some(idx) = match_target_idx(&finding.url, &matchers) {
            findings_by_target[idx].push(finding.clone());
        }
    }

    for err in &run_result.errors {
        let mapped_idx = err
            .url
            .as_deref()
            .and_then(|url| match_target_idx(url, &matchers));
        if let Some(idx) = mapped_idx {
            errors_by_target[idx].push(CapturedErrorRecord::from(err));
        } else {
            unscoped_errors = unscoped_errors.saturating_add(1);
        }
    }

    let generated_at = Utc::now().to_rfc3339();
    let mut per_target_json = Vec::with_capacity(targets.len());
    let mut target_summaries = Vec::with_capacity(targets.len());

    for (idx, target) in targets.iter().enumerate() {
        let discoveries = findings_by_target[idx].len();
        let errors = errors_by_target[idx].len();
        let summary = summarize_target_findings(&findings_by_target[idx], errors);
        let file_name = format!(
            "target-{:02}-{}.json",
            idx + 1,
            target_filename_slug(target)
        );
        let target_doc = TargetReportDocument {
            meta: TargetReportMeta {
                generated_at: generated_at.clone(),
                target: target.clone(),
                discoveries,
                errors,
            },
            summary,
            findings: findings_by_target[idx].clone(),
            errors: std::mem::take(&mut errors_by_target[idx]),
        };
        let target_json = serde_json::to_string_pretty(&target_doc).map_err(|e| e.to_string())?;
        per_target_json.push(TargetJsonExport {
            target: target.clone(),
            file_name,
            pretty_json: target_json,
        });

        target_summaries.push(TargetDiscoverySummary {
            target: target.clone(),
            discoveries,
            critical: target_doc.summary.critical,
            high: target_doc.summary.high,
            medium: target_doc.summary.medium,
            low: target_doc.summary.low,
            info: target_doc.summary.info,
            errors,
        });
    }

    let mut ranking_source = target_summaries.clone();
    ranking_source.sort_by(|a, b| {
        b.discoveries
            .cmp(&a.discoveries)
            .then_with(|| a.target.cmp(&b.target))
    });
    let discovery_ranking = ranking_source
        .into_iter()
        .enumerate()
        .map(|(idx, summary)| TargetDiscoveryRank {
            rank: idx + 1,
            target: summary.target,
            discoveries: summary.discoveries,
        })
        .collect();

    Ok((
        per_target_json,
        target_summaries,
        discovery_ranking,
        unscoped_errors,
    ))
}

fn build_insomnia_collection_export(
    targets: &[String],
    run_result: &runner::RunResult,
) -> Result<String, String> {
    let matchers = build_target_matchers(targets);
    let mut urls_by_target: Vec<BTreeMap<String, Vec<&Finding>>> =
        (0..targets.len()).map(|_| BTreeMap::new()).collect();

    for (idx, target) in targets.iter().enumerate() {
        urls_by_target[idx].entry(target.clone()).or_default();
    }

    for finding in &run_result.findings {
        if let Some(idx) = match_target_idx(&finding.url, &matchers) {
            urls_by_target[idx]
                .entry(finding.url.clone())
                .or_default()
                .push(finding);
        }
    }

    let mut target_items = Vec::with_capacity(targets.len());
    for (idx, target) in targets.iter().enumerate() {
        let mut request_items = Vec::new();
        for (url, findings) in &urls_by_target[idx] {
            let (name, description) = build_collection_request_details(url, findings);
            request_items.push(PostmanItem {
                name,
                item: None,
                request: Some(PostmanRequest {
                    method: "GET".to_string(),
                    header: vec![PostmanHeader {
                        key: "Accept".to_string(),
                        value: "application/json".to_string(),
                        kind: "text".to_string(),
                    }],
                    url: url.clone(),
                    description,
                }),
                response: Vec::new(),
            });
        }

        target_items.push(PostmanItem {
            name: format!("Target {} - {}", idx + 1, target),
            item: Some(request_items),
            request: None,
            response: Vec::new(),
        });
    }

    let collection = PostmanCollection {
        info: PostmanCollectionInfo {
            name: format!(
                "ApiHunter Discoveries {}",
                Utc::now().format("%Y-%m-%d %H:%M:%SZ")
            ),
            schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                .to_string(),
            description: "Generated by ApiHunter desktop. Import into Insomnia via Data > Import from File (Postman Collection v2.1).".to_string(),
        },
        item: target_items,
    };

    serde_json::to_string_pretty(&collection).map_err(|e| e.to_string())
}

fn build_collection_request_details(url: &str, findings: &[&Finding]) -> (String, String) {
    if findings.is_empty() {
        return (
            format!("Seed {}", url),
            "Seed target URL captured by ApiHunter.".to_string(),
        );
    }

    let max_severity = findings
        .iter()
        .map(|finding| &finding.severity)
        .max()
        .map(|sev| sev.label().trim().to_string())
        .unwrap_or_else(|| "INFO".to_string());

    let mut checks: BTreeMap<String, usize> = BTreeMap::new();
    for finding in findings {
        *checks.entry(finding.check.clone()).or_default() += 1;
    }
    let mut checks_vec: Vec<(String, usize)> = checks.into_iter().collect();
    checks_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut description_lines = vec![
        format!("Source URL: {url}"),
        format!("ApiHunter discoveries: {}", findings.len()),
        format!("Max severity: {max_severity}"),
        "Top checks:".to_string(),
    ];
    for (check, count) in checks_vec.into_iter().take(10) {
        description_lines.push(format!("- {check}: {count}"));
    }

    (
        format!("[{max_severity}] {url} ({} findings)", findings.len()),
        description_lines.join("\n"),
    )
}

fn build_insomnia_runner_data_export(
    targets: &[String],
    run_result: &runner::RunResult,
) -> Result<String, String> {
    let matchers = build_target_matchers(targets);
    let mut urls_by_target: Vec<BTreeMap<String, Vec<&Finding>>> =
        (0..targets.len()).map(|_| BTreeMap::new()).collect();

    for (idx, target) in targets.iter().enumerate() {
        urls_by_target[idx].entry(target.clone()).or_default();
    }

    for finding in &run_result.findings {
        if let Some(idx) = match_target_idx(&finding.url, &matchers) {
            urls_by_target[idx]
                .entry(finding.url.clone())
                .or_default()
                .push(finding);
        }
    }

    let mut rows = Vec::new();
    for (idx, target) in targets.iter().enumerate() {
        for (url, findings) in &urls_by_target[idx] {
            let mut checks: BTreeMap<String, usize> = BTreeMap::new();
            for finding in findings {
                *checks.entry(finding.check.clone()).or_default() += 1;
            }
            let top_check = checks
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
                .map(|(name, _)| name.clone())
                .unwrap_or_default();
            let max_severity = findings
                .iter()
                .map(|finding| &finding.severity)
                .max()
                .map(|sev| sev.label().trim().to_string())
                .unwrap_or_else(|| "INFO".to_string());
            rows.push(serde_json::json!({
                "iteration": rows.len() + 1,
                "target_index": idx + 1,
                "target": target,
                "url": url,
                "method": "GET",
                "findings_count": findings.len(),
                "max_severity": max_severity,
                "top_check": top_check,
            }));
        }
    }

    serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())
}

fn build_target_matchers(targets: &[String]) -> Vec<TargetMatcher> {
    targets
        .iter()
        .map(|target| {
            if let Ok(parsed) = url::Url::parse(target) {
                TargetMatcher {
                    host: parsed.host_str().unwrap_or("").to_ascii_lowercase(),
                    port: parsed.port_or_known_default(),
                    path_prefix: normalize_url_path(parsed.path()),
                }
            } else {
                TargetMatcher {
                    host: String::new(),
                    port: None,
                    path_prefix: "/".to_string(),
                }
            }
        })
        .collect()
}

fn match_target_idx(url: &str, matchers: &[TargetMatcher]) -> Option<usize> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port = parsed.port_or_known_default();
    let path = normalize_url_path(parsed.path());
    let mut best_match: Option<(usize, usize)> = None;

    for (idx, matcher) in matchers.iter().enumerate() {
        if matcher.host.is_empty() || matcher.host != host || matcher.port != port {
            continue;
        }
        if !path_matches_prefix(&path, &matcher.path_prefix) {
            continue;
        }

        let score = matcher.path_prefix.len();
        match best_match {
            Some((_, current_score)) if score <= current_score => {}
            _ => best_match = Some((idx, score)),
        }
    }

    best_match.map(|(idx, _)| idx)
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn normalize_url_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else {
        format!("/{}", trimmed.trim_start_matches('/').trim_end_matches('/'))
    }
}

fn target_filename_slug(target: &str) -> String {
    let mut pieces: Vec<String> = Vec::new();
    if let Ok(parsed) = url::Url::parse(target) {
        if let Some(host) = parsed.host_str() {
            pieces.push(host.to_string());
        }

        let path = parsed.path().trim_matches('/');
        if !path.is_empty() {
            pieces.extend(path.split('/').map(|segment| segment.to_string()));
        }
    } else {
        pieces.push(target.to_string());
    }

    let raw = pieces.join("-");
    sanitize_filename_component(&raw)
}

fn sanitize_filename_component(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-').trim_matches('.').to_string();
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed
    }
}

fn summarize_target_findings(findings: &[Finding], errors: usize) -> ReportSummary {
    let mut summary = ReportSummary {
        total: findings.len(),
        errors,
        ..ReportSummary::default()
    };

    for finding in findings {
        match finding.severity {
            Severity::Critical => summary.critical += 1,
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
            Severity::Info => summary.info += 1,
        }
    }

    summary
}

fn validate_path_component(raw: &str, field_name: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field_name} cannot be empty."));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(format!(
            "{field_name} contains unsupported path characters."
        ));
    }
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") {
        return Err(format!(
            "{field_name} contains unsupported path characters."
        ));
    }
    Ok(trimmed.to_string())
}

fn default_export_folder_name() -> String {
    format!("apihunter-export-{}", Utc::now().format("%Y%m%d-%H%M%S"))
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
