use async_trait::async_trait;
use dashmap::DashSet;
use serde::Deserialize;
use std::{collections::HashSet, fs, path::Path, sync::Arc};
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
    pub fn new(_config: &Config) -> Self {
        Self {
            templates: Arc::new(load_templates()),
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
    match_headers: Vec<NameValue>,
    #[serde(default)]
    status_any_of: Vec<u16>,
    #[serde(default)]
    body_contains_any: Vec<String>,
    #[serde(default)]
    body_contains_all: Vec<String>,
    #[serde(default)]
    context_path_contains_any: Vec<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

fn load_templates() -> Vec<CveTemplate> {
    let mut templates = Vec::new();
    let mut seen_checks = HashSet::new();

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
                eprintln!("Warning: failed to read CVE template dir '{}': {e}", dir.display());
                Vec::new()
            }
        };

        entries.sort();

        for path in entries {
            let raw = match fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Warning: failed to read CVE template file '{}': {e}", path.display());
                    continue;
                }
            };

            let parsed = match toml::from_str::<CveTemplateFile>(&raw) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Warning: failed to parse CVE template file '{}': {e}", path.display());
                    continue;
                }
            };

            for mut t in parsed.templates {
                if t.id.trim().is_empty()
                    || t.check.trim().is_empty()
                    || t.path.trim().is_empty()
                    || t.method.trim().is_empty()
                {
                    eprintln!(
                        "Warning: skipping invalid CVE template in '{}': id/check/path/method required",
                        path.display()
                    );
                    continue;
                }

                if !seen_checks.insert(t.check.to_ascii_lowercase()) {
                    continue;
                }

                if t.source.trim().is_empty() {
                    t.source = format!("apihunter:{}", path.display());
                }

                templates.push(t);
            }
        }
    }

    if templates.is_empty() {
        let raw = include_str!("../../assets/cve_templates.toml");
        match toml::from_str::<CveTemplateFile>(raw) {
            Ok(file) => return file.templates,
            Err(e) => {
                eprintln!("Warning: failed to parse fallback CVE template catalog: {e}");
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

        for tmpl in self.templates.iter() {
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

            let resp = match execute_template_request(client, &probe_url, tmpl).await {
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
    tmpl.context_path_contains_any
        .iter()
        .any(|hint| target_path.contains(&hint.to_ascii_lowercase()))
}

async fn execute_template_request(
    client: &HttpClient,
    probe_url: &str,
    tmpl: &CveTemplate,
) -> Result<HttpResponse, CapturedError> {
    let method = tmpl.method.to_ascii_uppercase();

    if method != "GET" {
        return Err(CapturedError::internal(format!(
            "Unsupported CVE template method '{}' for {}",
            tmpl.method, tmpl.id
        )));
    }

    if tmpl.headers.is_empty() {
        client.get(probe_url).await
    } else {
        let headers = tmpl
            .headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect::<Vec<_>>();
        client.get_with_headers(probe_url, &headers).await
    }
}

fn template_matches_response(tmpl: &CveTemplate, resp: &HttpResponse) -> bool {
    if !tmpl.status_any_of.is_empty() && !tmpl.status_any_of.contains(&resp.status) {
        return false;
    }

    let body_l = resp.body.to_ascii_lowercase();

    if !tmpl.body_contains_all.is_empty()
        && !tmpl
            .body_contains_all
            .iter()
            .all(|needle| body_l.contains(&needle.to_ascii_lowercase()))
    {
        return false;
    }

    if !tmpl.body_contains_any.is_empty()
        && !tmpl
            .body_contains_any
            .iter()
            .any(|needle| body_l.contains(&needle.to_ascii_lowercase()))
    {
        return false;
    }

    if !tmpl.match_headers.is_empty() {
        for hv in &tmpl.match_headers {
            let name_l = hv.name.to_ascii_lowercase();
            let want_l = hv.value.to_ascii_lowercase();
            let got = resp.headers.get(&name_l).map(|v| v.to_ascii_lowercase());
            if got.as_ref().map(|v| !v.contains(&want_l)).unwrap_or(true) {
                return false;
            }
        }
    }

    true
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

fn snippet(s: &str, max_chars: usize) -> String {
    let mut out = s.chars().take(max_chars).collect::<String>();
    if s.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}
