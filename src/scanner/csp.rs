// src/scanner/csp.rs

use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Severity},
};

use super::Scanner;

pub struct CspScanner;

impl CspScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

// Directives that must exist for a meaningful CSP
static REQUIRED_DIRECTIVES: &[&str] = &["default-src", "script-src", "object-src", "base-uri"];

// Source expressions that trivially bypass script restrictions
static UNSAFE_SOURCES: &[(&str, &str)] = &[
    (
        "'unsafe-inline'",
        "Allows inline scripts/styles — XSS mitigation lost.",
    ),
    (
        "'unsafe-eval'",
        "Allows eval() — bypasses script-src restrictions.",
    ),
    (
        "'unsafe-hashes'",
        "Allows execution of hashed inline handlers.",
    ),
    (
        "data:",
        "'data:' URI in script context allows arbitrary script execution.",
    ),
    ("http:", "Plain HTTP source allows MITM script injection."),
    ("*", "Wildcard source allows loading from any host."),
];

// CDN / JSONP-enabled hosts well-known for bypass gadgets
static BYPASS_HOSTS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"(?i)^(?:https?://)?cdn\.cloudflare\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?ajax\.googleapis\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?cdnjs\.cloudflare\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?cdn\.jsdelivr\.net(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?unpkg\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?rawgit\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?raw\.githubusercontent\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?stackpath\.bootstrapcdn\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?code\.jquery\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?yandex\.st(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?api\.twitter\.com(?:/[^\s]*)?$",
        r"(?i)^(?:https?://)?platform\.twitter\.com(?:/[^\s]*)?$",
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
            Some(v) => v.to_string(),
            None => {
                // Check report-only as informational
                if let Some(ro) = resp.header("content-security-policy-report-only") {
                    findings.push(Finding::new(
                        url,
                        "csp/report-only",
                        "CSP Report-Only",
                        Severity::Info,
                        "Only CSP Report-Only header present; policy is not enforced.",
                        "csp",
                    )
                    .with_evidence(format!(
                        "Content-Security-Policy-Report-Only: {ro}"
                    ))
                    .with_remediation(
                        "Deploy an enforcing Content-Security-Policy header after validating reports.",
                    ));
                } else {
                    findings.push(
                        Finding::new(
                            url,
                            "csp/missing",
                            "No CSP header",
                            Severity::Info,
                            "No Content-Security-Policy header detected. CSP is a defense-in-depth mechanism.",
                            "csp",
                        )
                        .with_remediation(
                            "Add a Content-Security-Policy header with least-privilege sources.",
                        ),
                    );
                }
                return (findings, errors);
            }
        };

        // ── Parse directives into a map ───────────────────────────────────────
        let directives = parse_csp(&csp_value);

        // ── Missing required directives ───────────────────────────────────────
        for req in REQUIRED_DIRECTIVES {
            if !directives.contains_key(*req) {
                // Missing directives are informational - not exploitable alone
                let severity = match *req {
                    "default-src" | "script-src" => Severity::Low, // More important but still not exploitable
                    _ => Severity::Info, // Other directives are nice-to-have
                };
                findings.push(
                    Finding::new(
                        url,
                        format!("csp/missing-directive/{req}"),
                        format!("CSP missing '{req}'"),
                        severity,
                        format!("CSP is missing the '{req}' directive. Not exploitable without an injection vulnerability."),
                        "csp",
                    )
                    .with_evidence(format!("Content-Security-Policy: {csp_value}"))
                    .with_remediation(format!(
                        "Add the '{req}' directive with a restrictive allowlist."
                    )),
                );
            }
        }

        // ── Unsafe source values ──────────────────────────────────────────────
        let script_sources = directives
            .get("script-src")
            .or_else(|| directives.get("default-src"))
            .cloned()
            .unwrap_or_default();

        for (token, desc) in UNSAFE_SOURCES {
            if script_sources.iter().any(|s| s.eq_ignore_ascii_case(token)) {
                // CSP weaknesses are not exploitable alone - downgrade to Low/Info
                let severity = match *token {
                    "*" => Severity::Medium, // Wildcard is worse - allows any domain
                    "'unsafe-inline'" | "'unsafe-eval'" => Severity::Low, // Common but needs XSS to exploit
                    _ => Severity::Info, // Other unsafe sources are informational
                };

                findings.push(
                    Finding::new(
                        url,
                        format!("csp/unsafe-source/{}", token.trim_matches('\'')),
                        format!("CSP unsafe source: {token}"),
                        severity,
                        format!("script-src contains '{token}': {desc} Note: Not exploitable without an injection vulnerability."),
                        "csp",
                    )
                    .with_evidence(format!("Content-Security-Policy: {csp_value}"))
                    .with_remediation(
                        "Remove unsafe script sources and use nonces or hashes for inline scripts.",
                    ),
                );
            }
        }

        // ── Known bypass-gadget CDN hosts ─────────────────────────────────────
        for source in &script_sources {
            for re in BYPASS_HOSTS.iter() {
                if re.is_match(source) {
                    findings.push(
                        Finding::new(
                            url,
                            "csp/bypassable-cdn",
                            "CSP bypassable CDN",
                            Severity::Medium,
                            format!(
                                "script-src allows '{source}', which hosts JSONP endpoints or \
                             third-party scripts that can bypass CSP."
                            ),
                            "csp",
                        )
                        .with_evidence(format!("Content-Security-Policy: {csp_value}"))
                        .with_remediation(
                            "Pin scripts with subresource integrity or self-host critical assets.",
                        ),
                    );
                    break;
                }
            }
        }

        // ── Frame ancestors / clickjacking ────────────────────────────────────
        if !directives.contains_key("frame-ancestors") {
            findings.push(Finding::new(
                url,
                "csp/missing-frame-ancestors",
                "CSP missing frame-ancestors",
                Severity::Low,
                "CSP lacks 'frame-ancestors' directive (clickjacking protection).",
                "csp",
            )
            .with_evidence(format!("Content-Security-Policy: {csp_value}"))
            .with_remediation(
                "Add 'frame-ancestors' with a strict allowlist (or 'none') to prevent clickjacking.",
            ));
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
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
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
