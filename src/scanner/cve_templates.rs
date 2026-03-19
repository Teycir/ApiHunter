use async_trait::async_trait;
use dashmap::DashSet;
use rand::seq::SliceRandom;
use regex::Regex;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method,
};
use serde::Deserialize;
use std::{collections::HashSet, fs, path::Path, sync::Arc};
use tracing::{error, info, warn};
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
    reports::{Finding, Severity},
};

use super::Scanner;

pub struct CveTemplateScanner {
    templates: Arc<Vec<CveTemplate>>,
    checked_host_templates: Arc<DashSet<String>>,
}

impl CveTemplateScanner {
    pub fn new(config: &Config) -> Self {
        Self {
            templates: Arc::new(load_templates(config.quiet)),
            checked_host_templates: Arc::new(DashSet::new()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct CveTemplateFile {
    #[serde(default)]
    templates: Vec<CveTemplate>,
}

#[derive(Debug, Clone, Deserialize)]
struct NameValue {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TemplateRequestStep {
    path: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: Vec<NameValue>,
    #[serde(default)]
    expect_status_any_of: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
struct CveTemplate {
    id: String,
    check: String,
    title: String,
    severity: String,
    detail: String,
    remediation: String,
    source: String,
    path: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: Vec<NameValue>,
    #[serde(default)]
    preflight_requests: Vec<TemplateRequestStep>,
    #[serde(default)]
    match_headers: Vec<NameValue>,
    #[serde(default)]
    status_any_of: Vec<u16>,
    #[serde(default)]
    body_contains_any: Vec<String>,
    #[serde(default)]
    body_contains_all: Vec<String>,
    #[serde(default)]
    body_regex_any: Vec<String>,
    #[serde(default)]
    body_regex_all: Vec<String>,
    #[serde(default)]
    header_regex_any: Vec<String>,
    #[serde(default)]
    header_regex_all: Vec<String>,
    #[serde(default)]
    context_path_contains_any: Vec<String>,
    #[serde(default)]
    baseline_status_any_of: Vec<u16>,
    #[serde(default)]
    baseline_body_contains_any: Vec<String>,
    #[serde(default)]
    baseline_body_contains_all: Vec<String>,
    #[serde(default)]
    baseline_match_headers: Vec<NameValue>,
}

fn default_method() -> String {
    "GET".to_string()
}

fn load_templates(quiet: bool) -> Vec<CveTemplate> {
    let mut templates = Vec::new();
    let mut seen_checks = HashSet::new();
    let mut skipped_invalid = 0usize;
    let mut skipped_unsafe = 0usize;
    let mut skipped_invalid_templates = Vec::new();
    let mut skipped_unsafe_templates = Vec::new();

    for dir in cve_template_dirs() {
        if !dir.exists() || !dir.is_dir() {
            continue;
        }

        let mut entries = match fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
                .collect::<Vec<_>>(),
            Err(e) => {
                warn!(
                    template_dir = %dir.display(),
                    error = %e,
                    "Failed to read CVE template directory"
                );
                Vec::new()
            }
        };

        entries.sort();

        for path in entries {
            let raw = match fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        template_path = %path.display(),
                        error = %e,
                        "Failed to read CVE template file"
                    );
                    continue;
                }
            };

            let parsed = match toml::from_str::<CveTemplateFile>(&raw) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        template_path = %path.display(),
                        error = %e,
                        "Failed to parse CVE template file"
                    );
                    continue;
                }
            };

            for mut t in parsed.templates {
                let template_key = format!("{} ({})", template_identity(&t.id), path.display());
                if t.id.trim().is_empty()
                    || t.check.trim().is_empty()
                    || t.path.trim().is_empty()
                    || t.method.trim().is_empty()
                {
                    skipped_invalid += 1;
                    skipped_invalid_templates
                        .push(format!("{template_key}: missing id/check/path/method"));
                    warn!(
                        template_path = %path.display(),
                        "Skipping invalid CVE template: id/check/path/method required"
                    );
                    continue;
                }

                if !is_supported_template_method(&t.method) {
                    skipped_invalid += 1;
                    skipped_invalid_templates
                        .push(format!("{template_key}: unsupported method '{}'", t.method));
                    warn!(
                        template_path = %path.display(),
                        template_id = %t.id,
                        method = %t.method,
                        "Skipping CVE template with unsupported method"
                    );
                    continue;
                }

                if !t.path.trim().starts_with('/') {
                    skipped_invalid += 1;
                    skipped_invalid_templates.push(format!(
                        "{template_key}: non-root-relative path '{}'",
                        t.path
                    ));
                    warn!(
                        template_path = %path.display(),
                        template_id = %t.id,
                        template_path_value = %t.path,
                        "Skipping CVE template with non-root-relative path"
                    );
                    continue;
                }

                if has_unresolved_request_placeholder(&t.path)
                    || headers_have_unresolved_placeholders(&t.headers)
                {
                    skipped_unsafe += 1;
                    skipped_unsafe_templates.push(format!(
                        "{template_key}: unresolved placeholder in path/headers"
                    ));
                    continue;
                }

                let mut invalid_preflight = false;
                t.preflight_requests.retain(|step| {
                    if step.path.trim().is_empty() || step.method.trim().is_empty() {
                        return false;
                    }
                    if !step.path.trim().starts_with('/') {
                        invalid_preflight = true;
                        return false;
                    }
                    if !is_supported_template_method(&step.method)
                        || has_unresolved_request_placeholder(&step.path)
                        || headers_have_unresolved_placeholders(&step.headers)
                    {
                        invalid_preflight = true;
                        return false;
                    }
                    true
                });

                if invalid_preflight {
                    skipped_unsafe += 1;
                    skipped_unsafe_templates.push(format!(
                        "{template_key}: invalid/unsafe preflight request metadata"
                    ));
                    continue;
                }

                let has_status_matcher = !t.status_any_of.is_empty();
                let has_evidence_matchers = template_has_response_evidence_matchers(&t);
                if !has_status_matcher && !has_evidence_matchers {
                    skipped_unsafe += 1;
                    skipped_unsafe_templates
                        .push(format!("{template_key}: no response matchers configured"));
                    continue;
                }
                if has_status_matcher && !has_evidence_matchers {
                    skipped_unsafe += 1;
                    skipped_unsafe_templates.push(format!(
                        "{template_key}: status-only matcher without body/header evidence"
                    ));
                    continue;
                }

                if is_root_probe_path(&t.path) {
                    if !t.context_path_contains_any.is_empty() {
                        info!(
                            template_path = %path.display(),
                            template_id = %t.id,
                            "Ignoring context_path_contains_any for root-path template"
                        );
                    }
                    t.context_path_contains_any.clear();
                } else {
                    t.context_path_contains_any =
                        normalize_context_hints(&t.context_path_contains_any);
                    if t.context_path_contains_any.is_empty() {
                        t.context_path_contains_any = derive_context_hints_from_path(&t.path);
                    }
                    if t.context_path_contains_any.is_empty() {
                        skipped_invalid += 1;
                        skipped_invalid_templates
                            .push(format!("{template_key}: empty/invalid context hints"));
                        warn!(
                            template_path = %path.display(),
                            template_id = %t.id,
                            "Skipping CVE template with empty/invalid context hints"
                        );
                        continue;
                    }
                }

                if t.source.trim().is_empty() {
                    t.source = format!("apihunter:{}", path.display());
                }

                if !seen_checks.insert(t.check.to_ascii_lowercase()) {
                    continue;
                }

                templates.push(t);
            }
        }
    }

    if templates.is_empty() {
        warn!("No CVE templates loaded from configured template directories");
    }
    if skipped_invalid > 0 || skipped_unsafe > 0 {
        warn!(
            skipped_invalid,
            skipped_unsafe,
            loaded = templates.len(),
            "CVE template loader skipped invalid/unsafe templates"
        );

        if quiet {
            if !skipped_invalid_templates.is_empty() {
                error!(
                    skipped_invalid,
                    templates = ?skipped_invalid_templates,
                    "CVE template loader invalid-template details"
                );
            }
            if !skipped_unsafe_templates.is_empty() {
                error!(
                    skipped_unsafe,
                    templates = ?skipped_unsafe_templates,
                    "CVE template loader unsafe-template details"
                );
            }
        } else {
            if !skipped_invalid_templates.is_empty() {
                info!(
                    skipped_invalid,
                    templates = ?skipped_invalid_templates,
                    "CVE template loader invalid-template details"
                );
            }
            if !skipped_unsafe_templates.is_empty() {
                info!(
                    skipped_unsafe,
                    templates = ?skipped_unsafe_templates,
                    "CVE template loader unsafe-template details"
                );
            }
        }
    }

    templates
}

fn cve_template_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = vec![Path::new("assets/cve_templates").to_path_buf()];

    if let Ok(extra) = std::env::var("APIHUNTER_CVE_TEMPLATE_DIRS") {
        for raw in extra.split(':') {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            dirs.push(Path::new(trimmed).to_path_buf());
        }
    }

    dirs
}

#[async_trait]
impl Scanner for CveTemplateScanner {
    fn name(&self) -> &'static str {
        "cve_templates"
    }

    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        if !config.active_checks || self.templates.is_empty() {
            return (Vec::new(), Vec::new());
        }

        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let parsed = match Url::parse(url) {
            Ok(u) if matches!(u.scheme(), "http" | "https") => u,
            _ => return (findings, errors),
        };

        let Some(host) = parsed.host_str() else {
            return (findings, errors);
        };
        let host = host.to_ascii_lowercase();
        let target_path = parsed.path().to_ascii_lowercase();

        let mut base = format!("{}://{}", parsed.scheme(), host);
        if let Some(port) = parsed.port() {
            base.push(':');
            base.push_str(&port.to_string());
        }

        let mut ordered_templates = self.templates.iter().collect::<Vec<_>>();
        if ordered_templates.len() > 1 {
            let mut rng = rand::thread_rng();
            ordered_templates.shuffle(&mut rng);
        }

        for tmpl in ordered_templates {
            if !template_context_matches(tmpl, &target_path) {
                continue;
            }

            let key = format!("{host}|{}", tmpl.id.to_ascii_lowercase());
            if !self.checked_host_templates.insert(key) {
                continue;
            }

            let probe_url = if tmpl.path.starts_with('/') {
                format!("{base}{}", tmpl.path)
            } else {
                format!("{base}/{}", tmpl.path)
            };

            match execute_preflight_chain(client, &base, tmpl).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            }

            if template_has_baseline_matchers(tmpl) {
                let baseline_resp = match client.get(&probe_url).await {
                    Ok(r) => r,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };
                if !template_matches_baseline_response(tmpl, &baseline_resp) {
                    continue;
                }
            }

            let resp = match execute_template_request(
                client,
                &probe_url,
                &tmpl.method,
                &tmpl.headers,
                &tmpl.id,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };

            if !template_matches_response(tmpl, &resp) {
                continue;
            }

            findings.push(
                Finding::new(
                    &probe_url,
                    &tmpl.check,
                    &tmpl.title,
                    parse_severity(&tmpl.severity),
                    format!("{}\nTemplate source: {}", tmpl.detail, tmpl.source),
                    "cve_templates",
                )
                .with_evidence(format!(
                    "Template: {}\nMethod: {}\nURL: {}\nStatus: {}\nBody snippet: {}",
                    tmpl.id,
                    tmpl.method,
                    probe_url,
                    resp.status,
                    snippet(&resp.body, 280)
                ))
                .with_remediation(&tmpl.remediation),
            );
        }

        (findings, errors)
    }
}

fn template_context_matches(tmpl: &CveTemplate, target_path: &str) -> bool {
    if tmpl.context_path_contains_any.is_empty() {
        return true;
    }

    let target_segments = path_segments(target_path);
    if target_segments.is_empty() {
        return false;
    }

    let mut specific_hints = Vec::new();
    let mut generic_hints = Vec::new();

    for hint in &tmpl.context_path_contains_any {
        let hint_segments = path_segments(hint);
        if hint_segments.is_empty() {
            continue;
        }

        if hint_segments.len() == 1 && is_generic_context_token(hint_segments[0]) {
            generic_hints.push(hint_segments);
        } else {
            specific_hints.push(hint_segments);
        }
    }

    let candidate_hints = if !specific_hints.is_empty() {
        specific_hints
    } else {
        generic_hints
    };

    if candidate_hints.is_empty() {
        return false;
    }

    candidate_hints
        .iter()
        .any(|hint| contains_segment_sequence(&target_segments, hint))
}

fn template_has_baseline_matchers(tmpl: &CveTemplate) -> bool {
    !tmpl.baseline_status_any_of.is_empty()
        || !tmpl.baseline_body_contains_any.is_empty()
        || !tmpl.baseline_body_contains_all.is_empty()
        || !tmpl.baseline_match_headers.is_empty()
}

async fn execute_template_request(
    client: &HttpClient,
    probe_url: &str,
    method_raw: &str,
    headers_raw: &[NameValue],
    template_id: &str,
) -> Result<HttpResponse, CapturedError> {
    let method = method_raw.to_ascii_uppercase();

    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return Err(CapturedError::internal(format!(
            "Unsupported CVE template method '{}' for {}",
            method_raw, template_id
        )));
    }

    let parsed_method = Method::from_bytes(method.as_bytes()).map_err(|e| {
        CapturedError::internal(format!(
            "Invalid CVE template method '{}' for {}: {}",
            method_raw, template_id, e
        ))
    })?;

    let headers = to_header_map(headers_raw);
    let extra = if headers.is_empty() {
        None
    } else {
        Some(headers)
    };
    client.request(parsed_method, probe_url, extra, None).await
}

async fn execute_preflight_chain(
    client: &HttpClient,
    base: &str,
    tmpl: &CveTemplate,
) -> Result<bool, CapturedError> {
    for step in &tmpl.preflight_requests {
        let url = build_template_url(base, &step.path);
        let resp =
            execute_template_request(client, &url, &step.method, &step.headers, &tmpl.id).await?;
        if !step.expect_status_any_of.is_empty()
            && !step.expect_status_any_of.contains(&resp.status)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn build_template_url(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn to_header_map(pairs: &[NameValue]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for pair in pairs {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(pair.name.as_bytes()),
            HeaderValue::from_str(&pair.value),
        ) {
            map.insert(name, value);
        }
    }
    map
}

struct ResponseMatchConstraints<'a> {
    status_any_of: &'a [u16],
    body_contains_any: &'a [String],
    body_contains_all: &'a [String],
    body_regex_any: &'a [String],
    body_regex_all: &'a [String],
    match_headers: &'a [NameValue],
    header_regex_any: &'a [String],
    header_regex_all: &'a [String],
}

fn template_matches_response(tmpl: &CveTemplate, resp: &HttpResponse) -> bool {
    let constraints = ResponseMatchConstraints {
        status_any_of: &tmpl.status_any_of,
        body_contains_any: &tmpl.body_contains_any,
        body_contains_all: &tmpl.body_contains_all,
        body_regex_any: &tmpl.body_regex_any,
        body_regex_all: &tmpl.body_regex_all,
        match_headers: &tmpl.match_headers,
        header_regex_any: &tmpl.header_regex_any,
        header_regex_all: &tmpl.header_regex_all,
    };
    response_matches_constraints(&constraints, resp)
}

fn template_matches_baseline_response(tmpl: &CveTemplate, resp: &HttpResponse) -> bool {
    let constraints = ResponseMatchConstraints {
        status_any_of: &tmpl.baseline_status_any_of,
        body_contains_any: &tmpl.baseline_body_contains_any,
        body_contains_all: &tmpl.baseline_body_contains_all,
        body_regex_any: &[],
        body_regex_all: &[],
        match_headers: &tmpl.baseline_match_headers,
        header_regex_any: &[],
        header_regex_all: &[],
    };
    response_matches_constraints(&constraints, resp)
}

fn response_matches_constraints(
    constraints: &ResponseMatchConstraints,
    resp: &HttpResponse,
) -> bool {
    if !constraints.status_any_of.is_empty() && !constraints.status_any_of.contains(&resp.status) {
        return false;
    }

    let body_l = resp.body.to_ascii_lowercase();

    if !constraints.body_contains_all.is_empty()
        && !constraints
            .body_contains_all
            .iter()
            .all(|needle| body_l.contains(&needle.to_ascii_lowercase()))
    {
        return false;
    }

    if !constraints.body_contains_any.is_empty()
        && !constraints
            .body_contains_any
            .iter()
            .any(|needle| body_l.contains(&needle.to_ascii_lowercase()))
    {
        return false;
    }

    if !constraints.body_regex_all.is_empty()
        && !constraints
            .body_regex_all
            .iter()
            .all(|pattern| regex_matches(pattern, &resp.body))
    {
        return false;
    }

    if !constraints.body_regex_any.is_empty()
        && !constraints
            .body_regex_any
            .iter()
            .any(|pattern| regex_matches(pattern, &resp.body))
    {
        return false;
    }

    if !constraints.match_headers.is_empty() {
        for hv in constraints.match_headers {
            let name_l = hv.name.to_ascii_lowercase();
            let want_l = hv.value.to_ascii_lowercase();
            let got = resp.headers.get(&name_l).map(|v| v.to_ascii_lowercase());
            if got.as_ref().map(|v| !v.contains(&want_l)).unwrap_or(true) {
                return false;
            }
        }
    }

    if !constraints.header_regex_all.is_empty() || !constraints.header_regex_any.is_empty() {
        let header_blob = resp
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}\n"))
            .collect::<String>();

        if !constraints.header_regex_all.is_empty()
            && !constraints
                .header_regex_all
                .iter()
                .all(|pattern| regex_matches(pattern, &header_blob))
        {
            return false;
        }
        if !constraints.header_regex_any.is_empty()
            && !constraints
                .header_regex_any
                .iter()
                .any(|pattern| regex_matches(pattern, &header_blob))
        {
            return false;
        }
    }

    true
}

fn regex_matches(pattern: &str, haystack: &str) -> bool {
    Regex::new(pattern)
        .map(|re| re.is_match(haystack))
        .unwrap_or(false)
}

fn parse_severity(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn is_supported_template_method(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

fn has_unresolved_request_placeholder(raw: &str) -> bool {
    let v = raw.trim();
    v.contains("{{") && v.contains("}}")
}

fn template_identity(id: &str) -> &str {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        "<missing-id>"
    } else {
        trimmed
    }
}

fn template_has_response_evidence_matchers(tmpl: &CveTemplate) -> bool {
    !tmpl.body_contains_any.is_empty()
        || !tmpl.body_contains_all.is_empty()
        || !tmpl.body_regex_any.is_empty()
        || !tmpl.body_regex_all.is_empty()
        || !tmpl.match_headers.is_empty()
        || !tmpl.header_regex_any.is_empty()
        || !tmpl.header_regex_all.is_empty()
}

fn headers_have_unresolved_placeholders(headers: &[NameValue]) -> bool {
    headers.iter().any(|h| {
        has_unresolved_request_placeholder(&h.name) || has_unresolved_request_placeholder(&h.value)
    })
}

fn normalize_context_hints(raw_hints: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for raw in raw_hints {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(normalized) = normalize_hint(trimmed) {
            if seen.insert(normalized.clone()) {
                out.push(normalized);
            }
        }
    }

    out
}

fn is_root_probe_path(path: &str) -> bool {
    path_segments(path).is_empty()
}

fn derive_context_hints_from_path(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for token in path_segments(path) {
        if token.starts_with('{') || token.contains("{{") || token.contains("}}") {
            continue;
        }
        let hint = format!("/{token}");
        if seen.insert(hint.clone()) {
            out.push(hint);
        }
        if out.len() >= 4 {
            break;
        }
    }
    out
}

fn normalize_hint(raw: &str) -> Option<String> {
    let canonical = raw.split('?').next().unwrap_or(raw).to_ascii_lowercase();
    let segments = path_segments(&canonical);
    if segments.is_empty() {
        return None;
    }
    if segments
        .iter()
        .any(|s| s.contains("{{") || s.contains("}}"))
    {
        return None;
    }
    Some(format!("/{}", segments.join("/")))
}

fn path_segments(path: &str) -> Vec<&str> {
    path.split('?')
        .next()
        .unwrap_or(path)
        .split('/')
        .filter_map(|seg| {
            let trimmed = seg.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect()
}

fn is_generic_context_token(token: &str) -> bool {
    matches!(
        token,
        "api"
            | "apis"
            | "rest"
            | "v1"
            | "v2"
            | "v3"
            | "v4"
            | "v5"
            | "latest"
            | "public"
            | "internal"
            | "service"
            | "services"
            | "console"
            | "ui"
            | "web"
            | "www"
            | "app"
            | "apps"
            | "default"
            | "index"
    )
}

fn contains_segment_sequence(target: &[&str], hint: &[&str]) -> bool {
    if hint.len() > target.len() {
        return false;
    }
    target.windows(hint.len()).any(|win| win == hint)
}

fn snippet(s: &str, max_chars: usize) -> String {
    let mut out = s.chars().take(max_chars).collect::<String>();
    if s.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}
