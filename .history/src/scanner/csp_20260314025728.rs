use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::{config::Config, error::CapturedError, http_client::HttpClient};

use super::{Finding, Scanner, Severity};

pub struct CspScanner;

// Directives that must exist for a meaningful CSP
static REQUIRED_DIRECTIVES: &[&str] = &[
    "default-src",
    "script-src",
    "object-src",
    "base-uri",
];

// Source expressions that trivially bypass script restrictions
static UNSAFE_SOURCES: &[(&str, &str)] = &[
    ("'unsafe-inline'",   "Allows inline scripts/styles — XSS mitigation lost."),
    ("'unsafe-eval'",     "Allows eval() — bypasses script-src restrictions."),
    ("'unsafe-hashes'",   "Allows execution of hashed inline handlers."),
    ("data:",             "'data:' URI in script context allows arbitrary script execution."),
    ("http:",             "Plain HTTP source allows MITM script injection."),
    ("*",                 "Wildcard source allows loading from any host."),
];

// CDN / JSONP-enabled hosts well-known for bypass gadgets
static BYPASS_HOSTS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"(?i)cdn\.cloudflare\.com",
        r"(?i)ajax\.googleapis\.com",
        r"(?i)cdnjs\.cloudflare\.com",
        r"(?i)cdn\.jsdelivr\.net",
        r"(?i)unpkg\.com",
        r"(?i)rawgit\.com",
        r"(?i)raw\.githubusercontent\.com",
        r"(?i)stackpath\.bootstrapcdn\.com",
        r"(?i)code\.jquery\.com",
        r"(?i)yandex\.st",
        r"(?i)api\.twitter\.com",
        r"(?i)platform\.twitter\.com",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

#[async_trait]
impl Scanner for CspScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        _config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let resp = match client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                return (findings, errors);
            }
        };

        // ── Header presence ───────────────────────────────────────────────────
        let csp_value = match resp.header("content-security-policy") {
            Some(v) => v,
            None => {
                // Check report-only as informational
                if let Some(ro) = resp.header("content-security-policy-report-only") {
                    findings.push(Finding {
                        url: url.to_string(),
                        check: "csp/report-only".to_string(),
                        severity: Severity::Info,
                        detail: "Only CSP Report-Only header present; policy is not enforced."
                            .to_string(),
                        evidence: Some(format!(
                            "Content-Security-Policy-Report-Only: {ro}"
                        )),
                    });
                } else {
                    findings.push(Finding {
                        url: url.to_string(),
                        check: "csp/missing".to_string(),
                        severity: Severity::Medium,
                        detail: "No Content-Security-Policy header detected.".to_string(),
                        evidence: None,
                    });
                }
                return (findings, errors);
            }
        };

        // ── Parse directives into a map ───────────────────────────────────────
        let directives = parse_csp(&csp_value);

        // ── Missing required directives ───────────────────────────────────────
        for req in REQUIRED_DIRECTIVES {
            if !directives.contains_key(*req) {
                // 'object-src' and 'base-uri' absence is only critical when
                // default-src is also missing or too permissive
                let severity = match *req {
                    "default-src" => Severity::Medium,
                    "script-src"  => Severity::Medium,
                    "object-src"  => Severity::Low,
                    "base-uri"    => Severity::Low,
                    _             => Severity::Info,
                };
                findings.push(Finding {
                    url: url.to_string(),
                    check: format!("csp/missing-directive/{req}"),
                    severity,
                    detail: format!("CSP is missing the '{req}' directive."),
                    evidence: Some(format!("Content-Security-Policy: {csp_value}")),
                });
            }
        }

        // ── Unsafe source values ──────────────────────────────────────────────
        // Check script-src first; fall back to default-src
        let script_sources = directives
            .get("script-src")
            .or_else(|| directives.get("default-src"))
            .cloned()
            .unwrap_or_default();

        for (token, desc) in UNSAFE_SOURCES {
            if script_sources
                .iter()
                .any(|s| s.eq_ignore_ascii_case(token))
            {
                findings.push(Finding {
                    url: url.to_string(),
                    check: format!("csp/unsafe-source/{}", token.trim_matches('\'')),
                    severity: Severity::High,
                    detail: format!("script-src contains '{token}': {desc}"),
                    evidence: Some(format!("Content-Security-Policy: {csp_value}")),
                });
            }
        }

        // ── Known bypass-gadget CDN hosts ─────────────────────────────────────
        for source in &script_sources {
            for re in BYPASS_HOSTS.iter() {
                if re.is_match(source) {
                    findings.push(Finding {
                        url: url.to_string(),
                        check: "csp/bypassable-cdn".to_string(),
                        severity: Severity::Medium,
                        detail: format!(
                            "script-src allows '{source}', which hosts JSONP endpoints or \
                             third-party scripts that can bypass CSP."
                        ),
                        evidence: Some(format!("Content-Security-Policy: {csp_value}")),
                    });
                    break;
                }
            }
        }

        // ── Frame ancestors / clickjacking ────────────────────────────────────
        if !directives.contains_key("frame-ancestors") {
            findings.push(Finding {
                url: url.to_string(),
                check: "csp/missing-frame-ancestors".to_string(),
                severity: Severity::Low,
                detail: "CSP lacks 'frame-ancestors' directive (clickjacking protection).".to_string(),
                evidence: Some(format!("Content-Security-Policy: {csp_value}")),
            });
        }

        (findings, errors)
    }
}

// ── CSP parser ────────────────────────────────────────────────────────────────

/// Returns a map of `directive_name → [source, ...]`.
fn parse_csp(header: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut map = std::collections::HashMap::new();

    for directive in header.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }
        let mut parts = directive.splitn(2, char::is_whitespace);
        let name = parts
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let sources: Vec<String> = parts
            .next()
            .unwrap_or("")
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        map.insert(name, sources);
    }

    map
}
