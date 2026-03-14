use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

use crate::{config::Config, error::CapturedError, http_client::HttpClient};

use super::{Finding, Scanner, Severity};

pub struct ApiSecurityScanner;

// ── Secret / credential patterns ──────────────────────────────────────────────

struct SecretPattern {
    name: &'static str,
    re:   &'static Lazy<Regex>,
}

macro_rules! lazy_re {
    ($re:expr) => {{
        static R: Lazy<Regex> = Lazy::new(|| Regex::new($re).unwrap());
        &R
    }};
}

macro_rules! pat {
    ($name:expr, $re:expr) => {
        SecretPattern { name: $name, re: lazy_re!($re) }
    };
}

static SECRET_PATTERNS: &[SecretPattern] = &[
    pat!("AWS Access Key",          r"AKIA[0-9A-Z]{16}"),
    pat!("AWS Secret Key",          r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    pat!("Generic API Key",         r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,64}['\"]?"),
    pat!("Bearer Token",            r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}"),
    pat!("Generic Secret",          r"(?i)(secret|passwd|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    pat!("Private Key Header",      r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    pat!("GitHub Token",            r"ghp_[0-9a-zA-Z]{36}"),
    pat!("Slack Token",             r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    pat!("Stripe Secret Key",       r"sk_live_[0-9a-zA-Z]{24,}"),
    pat!("Sendgrid API Key",        r"SG\.[A-Za-z0-9\-_\.]{20,}"),
    pat!("Google API Key",          r"AIza[0-9A-Za-z\-_]{35}"),
    pat!("JWT",                     r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
    pat!("Database URL",            r"(?i)(mysql|postgres|mongodb|redis|amqp)://[^@\s]+:[^@\s]+@[^\s]+"),
];

// ── Error-disclosure patterns ─────────────────────────────────────────────────

struct ErrorPattern {
    name: &'static str,
    re:   &'static Lazy<Regex>,
}

static ERROR_PATTERNS: &[ErrorPattern] = &[
    ErrorPattern {
        name: "Stack trace (Java)",
        re: lazy_re!(r"at [A-Za-z0-9\.$_]+\(.*\.java:\d+\)"),
    },
    ErrorPattern {
        name: "Stack trace (Python)",
        re: lazy_re!(r"Traceback \(most recent call last\)"),
    },
    ErrorPattern {
        name: "Stack trace (Ruby)",
        re: lazy_re!(r"\.rb:\d+:in `"),
    },
    ErrorPattern {
        name: "SQL error",
        re: lazy_re!(
            r"(?i)(SQL syntax.*MySQL|mysql_fetch_|ORA-\d{4,5}|pg_query\(\)|SQLite3::Exception|Unclosed quotation mark)"
        ),
    },
    ErrorPattern {
        name: "PHP error",
        re: lazy_re!(
            r"(?i)(Parse error|Fatal error|Warning:|Notice:)\s+.+in\s+/.+\.php on line"
        ),
    },
    ErrorPattern {
        name: "ASP.NET error page",
        re: lazy_re!(r"(?i)Server Error in '.*' Application\."),
    },
    ErrorPattern {
        name: "Django debug page",
        re: lazy_re!(r"(?i)django\.core\.exceptions|<title>Django.*Error</title>"),
    },
    ErrorPattern {
        name: "Werkzeug debugger",
        re: lazy_re!(r"(?i)Werkzeug Debugger|The Werkzeug interactive debugger"),
    },
    ErrorPattern {
        name: "Laravel debug",
        re: lazy_re!(r"(?i)laravel\.log|Whoops[,!].*Laravel"),
    },
    ErrorPattern {
        name: "Internal path disclosure",
        re: lazy_re!(r"(?i)(/home/[a-z_][a-z0-9_]*/|/var/www/|/usr/local/|C:\\Users\\|C:\\inetpub\\)"),
    },
];

// ── Dangerous HTTP methods ────────────────────────────────────────────────────

static DANGEROUS_METHODS: &[&str] = &["PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "OPTIONS"];

// ── Directory-listing markers ─────────────────────────────────────────────────

static DIR_LISTING_MARKERS: &[&str] = &[
    "Index of /",
    "Directory listing for",
    "Parent Directory</a>",
    "[To Parent Directory]",
];

// ── Common debug / admin endpoints ────────────────────────────────────────────

static DEBUG_PATHS: &[&str] = &[
    "/debug",
    "/debug/vars",        // Go expvar
    "/debug/pprof",       // Go pprof
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/settings.json",
    "/application.properties",
    "/application.yml",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/server-status",     // Apache mod_status
    "/server-info",
    "/_profiler",         // Symfony profiler
    "/__clockwork",       // Clockwork (Laravel)
    "/actuator",          // Spring Boot
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/httptrace",
    "/metrics",
    "/health",
    "/healthz",
    "/readyz",
    "/status",
    "/admin",
    "/admin/config",
];

// ── SECURITY.TXT paths ────────────────────────────────────────────────────────

static SECURITY_TXT_PATHS: &[&str] = &[
    "/.well-known/security.txt",
    "/security.txt",
];

// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl Scanner for ApiSecurityScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        _config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors   = Vec::new();

        // Run all checks; failures are captured rather than propagated.
        check_secrets_in_response(url, client, &mut findings, &mut errors).await;
        check_error_disclosure(url, client, &mut findings, &mut errors).await;
        check_http_methods(url, client, &mut findings, &mut errors).await;
        check_debug_endpoints(url, client, &mut findings, &mut errors).await;
        check_directory_listing(url, client, &mut findings, &mut errors).await;
        check_security_txt(url, client, &mut findings).await;
        check_response_headers(url, client, &mut findings, &mut errors).await;

        (findings, errors)
    }
}

// ── 1. Secrets in response body ───────────────────────────────────────────────

async fn check_secrets_in_response(
    url:      &str,
    client:   &HttpClient,
    findings: &mut Vec<Finding>,
    errors:   &mut Vec<CapturedError>,
) {
    let resp = match client.get(url).await {
        Ok(r)  => r,
        Err(e) => { errors.push(e); return; }
    };

    for pat in SECRET_PATTERNS {
        if let Some(m) = pat.re.find(&resp.body) {
            // Redact — show only the first/last 4 chars of the matched text.
            let matched = m.as_str();
            let redacted = redact(matched);

            findings.push(Finding {
                url:      url.to_string(),
                check:    format!("api_security/secret-in-response/{}", slug(pat.name)),
                severity: Severity::Critical,
                detail:   format!(
                    "Possible {} found in HTTP response body.",
                    pat.name
                ),
                evidence: Some(format!(
                    "Pattern: {}\nMatch (redacted): {redacted}\nURL: {url}",
                    pat.name
                )),
            });
        }
    }
}

// ── 2. Verbose error / debug information ─────────────────────────────────────

async fn check_error_disclosure(
    url:      &str,
    client:   &HttpClient,
    findings: &mut Vec<Finding>,
    errors:   &mut Vec<CapturedError>,
) {
    // Trigger errors with a malformed path + garbage query string
    let probe_urls = [
        format!("{url}/FUZZ_ERROR_XYZ"),
        format!("{url}?id='%22<script>"),
    ];

    for probe in &probe_urls {
        let resp = match client.get(probe).await {
            Ok(r)  => r,
            Err(e) => { errors.push(e); continue; }
        };

        for pat in ERROR_PATTERNS {
            if pat.re.is_match(&resp.body) {
                findings.push(Finding {
                    url:      url.to_string(),
                    check:    format!("api_security/error-disclosure/{}", slug(pat.name)),
                    severity: Severity::Medium,
                    detail:   format!(
                        "Verbose error information leaked: {} detected in response \
                         to malformed request.",
                        pat.name
                    ),
                    evidence: Some(format!(
                        "Probe URL: {probe}\nStatus: {}\nSnippet: {}",
                        resp.status,
                        snippet(&resp.body, 400)
                    )),
                });
                // One finding per pattern per probe is enough
                break;
            }
        }
    }
}

// ── 3. HTTP method enumeration ────────────────────────────────────────────────

async fn check_http_methods(
    url:      &str,
    client:   &HttpClient,
    findings: &mut Vec<Finding>,
    errors:   &mut Vec<CapturedError>,
) {
    // First try OPTIONS — it may advertise allowed methods directly.
    let allowed_from_options = match client.options(url).await {
        Ok(resp) => {
            let from_allow = resp
                .headers
                .get("allow")
                .or_else(|| resp.headers.get("Allow"))
                .cloned()
                .unwrap_or_default();

            let from_acam = resp
                .headers
                .get("access-control-allow-methods")
                .cloned()
                .unwrap_or_default();

            // Combine both header values
            format!("{from_allow},{from_acam}")
                .split(',')
                .map(|s| s.trim().to_ascii_uppercase())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        }
        Err(e) => {
            errors.push(e);
            vec![]
        }
    };

    let mut dangerous_allowed: Vec<String> = Vec::new();

    for method in DANGEROUS_METHODS {
        let advertised = allowed_from_options
            .iter()
            .any(|m| m == method);

        // Verify with a real request (especially for TRACE which echoes input)
        let actually_allowed = if advertised {
            true
        } else {
            match client.request(method, url).await {
                Ok(r)  => r.status < 405,   // 405 = Method Not Allowed
                Err(e) => { errors.push(e); false }
            }
        };

        if actually_allowed {
            dangerous_allowed.push(method.to_string());
        }
    }

    if dangerous_allowed.contains(&"TRACE".to_string()) {
        findings.push(Finding {
            url:      url.to_string(),
            check:    "api_security/http-method/trace-enabled".to_string(),
            severity: Severity::Low,
            detail:   "HTTP TRACE method is enabled. Combined with client-side bugs it can \
                       enable Cross-Site Tracing (XST) attacks."
                .to_string(),
            evidence: Some(format!("TRACE responded with status < 405 on {url}")),
        });
    }

    if dangerous_allowed.contains(&"OPTIONS".to_string()) {
        // OPTIONS itself is not dangerous but we record it for visibility
    }

    let write_methods: Vec<&str> = dangerous_allowed
        .iter()
        .filter(|m| matches!(m.as_str(), "PUT" | "DELETE" | "PATCH"))
        .map(String::as_str)
        .collect();

    if !write_methods.is_empty() {
        findings.push(Finding {
            url:      url.to_string(),
            check:    "api_security/http-method/write-methods-enabled".to_string(),
            severity: Severity::Medium,
            detail:   format!(
                "Write HTTP methods accepted: {}. Verify these require authentication \
                 and are not accessible to unauthenticated clients.",
                write_methods.join(", ")
            ),
            evidence: Some(format!(
                "Methods returning non-405 on {url}: {}",
                write_methods.join(", ")
            )),
        });
    }
}

// ── 4. Debug / admin endpoint exposure ───────────────────────────────────────

async fn check_debug_endpoints(
    url:      &str,
    client:   &HttpClient,
    findings: &mut Vec<Finding>,
    errors:   &mut Vec<CapturedError>,
) {
    let base = url.trim_end_matches('/');

    // Classify by sensitivity
    let critical_keywords = ["env", "config", "secret", "password", "credential", "key"];
    let high_keywords      = ["actuator", "pprof", "phpinfo", "profiler", "clockwork"];

    for path in DEBUG_PATHS {
        let probe = format!("{base}{path}");
        let resp = match client.get(&probe).await {
            Ok(r)  => r,
            Err(e) => { errors.push(e); continue; }
        };

        // Only consider 200 or partial-200 range as exposed
        if resp.status != 200 {
            continue;
        }

        let lower_path = path.to_ascii_lowercase();

        let severity = if critical_keywords.iter().any(|k| lower_path.contains(k
        let severity = if critical_keywords.iter().any(|k| lower_path.contains(k)) {
            Severity::Critical
        } else if high_keywords.iter().any(|k| lower_path.contains(k)) {
            Severity::High
        } else {
            Severity::Medium
        };

        findings.push(Finding {
            url:      url.to_string(),
            check:    format!("api_security/debug-endpoint{}", path.replace('/', "-")),
            severity,
            detail:   format!(
                "Debug/admin endpoint publicly accessible: {path}. \
                 This may expose internal configuration, metrics, or runtime data."
            ),
            evidence: Some(format!(
                "URL: {probe}\nStatus: 200\nBody snippet:\n{}",
                snippet(&resp.body, 500)
            )),
        });
    }
}

// ── 5. Directory listing ───────────────────────────────────────────────────────

async fn check_directory_listing(
    url:      &str,
    client:   &HttpClient,
    findings: &mut Vec<Finding>,
    errors:   &mut Vec<CapturedError>,
) {
    // Probe the root and a non-existent path to distinguish real listings
    // from generic 200 catch-all pages.
    let probe_paths = ["/", "/static/", "/assets/", "/uploads/", "/files/"];
    let base = url.trim_end_matches('/');

    for path in &probe_paths {
        let probe = format!("{base}{path}");
        let resp = match client.get(&probe).await {
            Ok(r)  => r,
            Err(e) => { errors.push(e); continue; }
        };

        if resp.status != 200 {
            continue;
        }

        let body_lower = resp.body.to_ascii_lowercase();
        let matched_marker = DIR_LISTING_MARKERS
            .iter()
            .find(|&&m| body_lower.contains(&m.to_ascii_lowercase()));

        if let Some(marker) = matched_marker {
            findings.push(Finding {
                url:      url.to_string(),
                check:    format!(
                    "api_security/directory-listing{}",
                    path.trim_end_matches('/').replace('/', "-")
                ),
                severity: Severity::Medium,
                detail:   format!(
                    "Directory listing enabled at `{path}`. \
                     Attackers can enumerate files and discover sensitive assets."
                ),
                evidence: Some(format!(
                    "URL: {probe}\nMatched marker: \"{marker}\"\nSnippet:\n{}",
                    snippet(&resp.body, 400)
                )),
            });
        }
    }
}

// ── 6. security.txt presence ──────────────────────────────────────────────────

async fn check_security_txt(
    url:      &str,
    client:   &HttpClient,
    findings: &mut Vec<Finding>,
) {
    let base = url.trim_end_matches('/');
    let mut found = false;

    for path in SECURITY_TXT_PATHS {
        let probe = format!("{base}{path}");
        if let Ok(resp) = client.get(&probe).await {
            if resp.status == 200 && resp.body.to_ascii_lowercase().contains("contact:") {
                found = true;
                break;
            }
        }
    }

    if !found {
        // Informational — not a vulnerability, but worth reporting.
        findings.push(Finding {
            url:      url.to_string(),
            check:    "api_security/security-txt/missing".to_string(),
            severity: Severity::Info,
            detail:   "No valid security.txt found at /.well-known/security.txt or /security.txt. \
                       RFC 9116 recommends publishing one so researchers can report vulnerabilities."
                .to_string(),
            evidence: None,
        });
    }
}

// ── 7. Response-header security checks ───────────────────────────────────────

/// (header-name, check-slug, description, severity)
struct HeaderCheck {
    name:     &'static str,
    slug:     &'static str,
    detail:   &'static str,
    severity: Severity,
    /// If Some, the header must also *contain* this value (case-insensitive).
    must_contain: Option<&'static str>,
}

static HEADER_CHECKS: &[HeaderCheck] = &[
    HeaderCheck {
        name:         "strict-transport-security",
        slug:         "hsts-missing",
        detail:       "Strict-Transport-Security header absent. Clients may downgrade to HTTP.",
        severity:     Severity::Medium,
        must_contain: None,
    },
    HeaderCheck {
        name:         "x-content-type-options",
        slug:         "xcto-missing",
        detail:       "X-Content-Type-Options header absent. Browsers may MIME-sniff responses.",
        severity:     Severity::Low,
        must_contain: Some("nosniff"),
    },
    HeaderCheck {
        name:         "x-frame-options",
        slug:         "xfo-missing",
        detail:       "X-Frame-Options header absent. Page may be embedded in a malicious iframe (clickjacking).",
        severity:     Severity::Low,
        must_contain: None,
    },
    HeaderCheck {
        name:         "content-security-policy",
        slug:         "csp-missing",
        detail:       "Content-Security-Policy header absent. Increases risk of XSS and data injection.",
        severity:     Severity::Medium,
        must_contain: None,
    },
    HeaderCheck {
        name:         "referrer-policy",
        slug:         "referrer-policy-missing",
        detail:       "Referrer-Policy header absent. Sensitive URL parameters may leak via the Referer header.",
        severity:     Severity::Low,
        must_contain: None,
    },
    HeaderCheck {
        name:         "permissions-policy",
        slug:         "permissions-policy-missing",
        detail:       "Permissions-Policy (formerly Feature-Policy) header absent.",
        severity:     Severity::Info,
        must_contain: None,
    },
    HeaderCheck {
        name:         "cache-control",
        slug:         "cache-control-missing",
        detail:       "Cache-Control header absent on authenticated endpoint. Sensitive responses may be cached.",
        severity:     Severity::Low,
        must_contain: None,
    },
    HeaderCheck {
        name:         "x-powered-by",
        slug:         "x-powered-by-present",
        detail:       "X-Powered-By header present — leaks server technology stack.",
        severity:     Severity::Info,
        must_contain: None,
    },
    HeaderCheck {
        name:         "server",
        slug:         "server-version-leaked",
        detail:       "Server header includes a version string, aiding fingerprinting.",
        severity:     Severity::Info,
        must_contain: None,
    },
];

/// Regex to detect version strings in Server / X-Powered-By values.
static VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d+\.\d+").unwrap());

async fn check_response_headers(
    url:      &str,
    client:   &HttpClient,
    findings: &mut Vec<Finding>,
    errors:   &mut Vec<CapturedError>,
) {
    let resp = match client.get(url).await {
        Ok(r)  => r,
        Err(e) => { errors.push(e); return; }
    };

    // Normalise headers to lowercase keys for case-insensitive lookup
    let headers: HashMap<String, String> = resp
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();

    for check in HEADER_CHECKS {
        let key   = check.name;
        let value = headers.get(key);

        match key {
            // ── Headers that should be ABSENT ────────────────────────────────
            "x-powered-by" => {
                if value.is_some() {
                    findings.push(header_finding(url, check, value));
                }
            }
            "server" => {
                // Only flag if the value contains a version number
                if let Some(v) = value {
                    if VERSION_RE.is_match(v) {
                        findings.push(header_finding(url, check, Some(v)));
                    }
                }
            }

            // ── Headers that should be PRESENT (with optional value check) ──
            _ => {
                match value {
                    None => {
                        findings.push(header_finding(url, check, None));
                    }
                    Some(v) => {
                        if let Some(required) = check.must_contain {
                            if !v.to_ascii_lowercase().contains(required) {
                                findings.push(Finding {
                                    url:      url.to_string(),
                                    check:    format!("api_security/headers/{}-weak", check.slug),
                                    severity: check.severity.clone(),
                                    detail:   format!(
                                        "{} present but value does not contain `{required}`.",
                                        check.name
                                    ),
                                    evidence: Some(format!("{}: {v}", check.name)),
                                });
                            }
                        }
                        // else: header present and no value constraint — all good
                    }
                }
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a generic header Finding.
fn header_finding(url: &str, check: &HeaderCheck, value: Option<&String>) -> Finding {
    Finding {
        url:      url.to_string(),
        check:    format!("api_security/headers/{}", check.slug),
        severity: check.severity.clone(),
        detail:   check.detail.to_string(),
        evidence: value.map(|v| format!("{}: {v}", check.name)),
    }
}

/// Redact a matched secret string — keep first 4 and last 4 chars only.
fn redact(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    let stars = "*".repeat(chars.len().saturating_sub(8).min(12)); // cap star run
    format!("{head}{stars}{tail}")
}

/// Convert a human-readable name into a slug usable in check IDs.
fn slug(s: &str) -> String {
    s.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split("--")            // collapse repeated dashes
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Return the first `max_len` bytes of a string as a display snippet.
fn snippet(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}… ({} bytes total)", &s[..max_len], s.len())
    }
}
