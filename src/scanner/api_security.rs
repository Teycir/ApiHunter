// src/scanner/api_security.rs
//
// Checks: secrets in responses, error disclosure, HTTP methods,
// debug/admin endpoints, directory listing, security.txt, response headers.
//
// False-positive mitigation:
//   • SPA catch-all detection: fetches a known-404 "canary" path before
//     probing debug endpoints.  If the canary returns 200 + HTML, the site
//     uses client-side routing and all 200-HTML responses are ignored.
//   • Content-Type guard: real config / debug endpoints respond with JSON,
//     plain text, YAML, or XML — not text/html.
//   • Body-content validation: specific endpoints must contain expected
//     patterns (e.g. actuator returns JSON, .env contains KEY=VAL).

use async_trait::async_trait;
use dashmap::DashSet;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use regex::Regex;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::debug;
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
    reports::{Confidence, Finding, Severity},
};

use super::{
    common::http_utils::is_html_content_type as common_is_html_content_type,
    common::sequence::{SequenceActor, SequenceRunner, SequenceStep, SequenceStepResult},
    common::string_utils::{redact_secret, slugify, snippet as shared_snippet},
    Scanner,
};

pub struct ApiSecurityScanner {
    client_b: Option<Arc<HttpClient>>,
    checked_hosts: Arc<DashSet<String>>,
    ssrf_checked_paths: Arc<DashSet<String>>,
    gateway_checked_paths: Arc<DashSet<String>>,
}

impl ApiSecurityScanner {
    pub fn new(_config: &Config, client_b: Option<Arc<HttpClient>>) -> Self {
        Self {
            client_b,
            checked_hosts: Arc::new(DashSet::new()),
            ssrf_checked_paths: Arc::new(DashSet::new()),
            gateway_checked_paths: Arc::new(DashSet::new()),
        }
    }
}

// ── Secret / credential patterns ──────────────────────────────────────────────

static RE_AWS_ACCESS: Lazy<Regex> = Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").unwrap());
static RE_AWS_SECRET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#).unwrap());
static RE_API_KEY: Lazy<Regex> = Lazy::new(|| {
    // Match api_key/apikey patterns with or without quotes
    // Minimum 16 chars to balance false positives vs recall
    Regex::new(r#"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9\-_]{16,64})['"]?"#)
        .expect("Invalid API_KEY regex")
});

static RE_BEARER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}").expect("Invalid BEARER regex"));
static RE_GENERIC_SEC: Lazy<Regex> = Lazy::new(|| {
    // Keep minimum at 12 chars with quotes to catch real secrets
    // Require at least one alphanumeric to avoid matching empty/whitespace values
    Regex::new(r#"(?i)(secret|passwd|password)\s*[:=]\s*['"]([^'"]{12,})['"]"#)
        .expect("Invalid GENERIC_SEC regex")
});
static RE_PRIVATE_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap());
static RE_GITHUB: Lazy<Regex> = Lazy::new(|| Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap());
static RE_SLACK: Lazy<Regex> = Lazy::new(|| Regex::new(r"xox[baprs]-[0-9a-zA-Z\-]{10,}").unwrap());
static RE_STRIPE: Lazy<Regex> = Lazy::new(|| Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap());
static RE_SENDGRID: Lazy<Regex> = Lazy::new(|| Regex::new(r"SG\.[A-Za-z0-9\-_\.]{20,}").unwrap());
static RE_GOOGLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap());
static RE_DB_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(mysql|postgres|mongodb|redis|amqp)://[^@\s]+:[^@\s]+@[^\s]+").unwrap()
});

struct SecretCheck {
    name: &'static str,
    re: &'static Lazy<Regex>,
}

static SECRET_CHECKS: &[SecretCheck] = &[
    SecretCheck {
        name: "AWS Access Key",
        re: &RE_AWS_ACCESS,
    },
    SecretCheck {
        name: "AWS Secret Key",
        re: &RE_AWS_SECRET,
    },
    SecretCheck {
        name: "Generic API Key",
        re: &RE_API_KEY,
    },
    SecretCheck {
        name: "Bearer Token",
        re: &RE_BEARER,
    },
    SecretCheck {
        name: "Generic Secret",
        re: &RE_GENERIC_SEC,
    },
    SecretCheck {
        name: "Private Key Header",
        re: &RE_PRIVATE_KEY,
    },
    SecretCheck {
        name: "GitHub Token",
        re: &RE_GITHUB,
    },
    SecretCheck {
        name: "Slack Token",
        re: &RE_SLACK,
    },
    SecretCheck {
        name: "Stripe Secret Key",
        re: &RE_STRIPE,
    },
    SecretCheck {
        name: "Sendgrid API Key",
        re: &RE_SENDGRID,
    },
    SecretCheck {
        name: "Google API Key",
        re: &RE_GOOGLE,
    },
    SecretCheck {
        name: "Database URL",
        re: &RE_DB_URL,
    },
];

// ── Error-disclosure patterns ─────────────────────────────────────────────────

static RE_ERR_JAVA: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"at [A-Za-z0-9\.$_]+\(.*\.java:\d+\)").unwrap());
static RE_ERR_PYTHON: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Traceback \(most recent call last\)").unwrap());
static RE_ERR_RUBY: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.rb:\d+:in `").unwrap());
static RE_ERR_SQL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(SQL syntax.*MySQL|mysql_fetch_|ORA-\d{4,5}|pg_query\(\)|SQLite3::Exception|Unclosed quotation mark)").unwrap()
});
static RE_ERR_PHP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(Parse error|Fatal error|Warning:|Notice:)\s+.+in\s+/.+\.php on line").unwrap()
});
static RE_ERR_ASP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)Server Error in '.*' Application\.").unwrap());
static RE_ERR_DJANGO: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)django\.core\.exceptions|<title>Django.*Error</title>").unwrap());
static RE_ERR_WERKZEUG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)Werkzeug Debugger|The Werkzeug interactive debugger").unwrap());
static RE_ERR_LARAVEL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)laravel\.log|Whoops[,!].*Laravel").unwrap());
static RE_ERR_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(/home/[a-z_][a-z0-9_]*/|/var/www/|/usr/local/|C:\\Users\\|C:\\inetpub\\)")
        .unwrap()
});

struct ErrorCheck {
    name: &'static str,
    re: &'static Lazy<Regex>,
}

static ERROR_CHECKS: &[ErrorCheck] = &[
    ErrorCheck {
        name: "Stack trace (Java)",
        re: &RE_ERR_JAVA,
    },
    ErrorCheck {
        name: "Stack trace (Python)",
        re: &RE_ERR_PYTHON,
    },
    ErrorCheck {
        name: "Stack trace (Ruby)",
        re: &RE_ERR_RUBY,
    },
    ErrorCheck {
        name: "SQL error",
        re: &RE_ERR_SQL,
    },
    ErrorCheck {
        name: "PHP error",
        re: &RE_ERR_PHP,
    },
    ErrorCheck {
        name: "ASP.NET error page",
        re: &RE_ERR_ASP,
    },
    ErrorCheck {
        name: "Django debug page",
        re: &RE_ERR_DJANGO,
    },
    ErrorCheck {
        name: "Werkzeug debugger",
        re: &RE_ERR_WERKZEUG,
    },
    ErrorCheck {
        name: "Laravel debug",
        re: &RE_ERR_LARAVEL,
    },
    ErrorCheck {
        name: "Internal path disclosure",
        re: &RE_ERR_PATH,
    },
];

// ── Dangerous HTTP methods ────────────────────────────────────────────────────

static DANGEROUS_METHODS: &[&str] = &["PUT", "DELETE", "PATCH", "TRACE"];

// ── Directory-listing markers ─────────────────────────────────────────────────

static DIR_LISTING_MARKERS: &[&str] = &[
    "Index of /",
    "Directory listing for",
    "Parent Directory</a>",
    "[To Parent Directory]",
];

// ── Common debug / admin endpoints ────────────────────────────────────────────

struct DebugEndpoint {
    path: &'static str,
    /// Expected content-types; if empty, any non-HTML is accepted.
    expected_ct: &'static [&'static str],
    /// Body must match at least one of these patterns to be considered genuine.
    body_validators: &'static [fn(&str) -> bool],
}

/// Returns `true` when the body looks like a dotenv file (`KEY=VALUE` lines).
fn is_dotenv(body: &str) -> bool {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^[A-Z_][A-Z0-9_]*=.+").unwrap());
    RE.is_match(body)
}

/// Returns `true` when the body parses as JSON and is not wrapped in HTML.
/// Also checks that it's not just an error response.
fn is_json_body(body: &str) -> bool {
    let trimmed = body.trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return false;
    }

    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(v) => {
            // Check if this is an array with error objects
            if let Some(arr) = v.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(obj) = first.as_object() {
                        // Pattern: [{"Status":"404","Message":"..."}]
                        if let Some(status) = obj.get("Status").and_then(|s| s.as_str()) {
                            if status == "404"
                                || status == "403"
                                || status.parse::<u16>().map(|c| c >= 400).unwrap_or(false)
                            {
                                return false;
                            }
                        }
                    }
                }
            }

            // Check if this is just an error response
            if let Some(obj) = v.as_object() {
                // Common error response patterns
                let has_error = obj.contains_key("error")
                    || obj.contains_key("errors")
                    || obj.contains_key("message")
                        && obj
                            .get("message")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_lowercase().contains("error"))
                            .unwrap_or(false);

                let has_status = obj
                    .get("status")
                    .and_then(|s| s.as_u64())
                    .map(|code| code >= 400)
                    .unwrap_or(false)
                    || obj
                        .get("statusCode")
                        .and_then(|s| s.as_u64())
                        .map(|code| code >= 400)
                        .unwrap_or(false);
                // If it's just an error response with no other meaningful data, reject it
                if has_error && (has_status || obj.len() <= 3) {
                    return false;
                }
            }
            true
        }
        Err(_) => false,
    }
}

/// Returns `true` when the body looks like YAML config (has key: value lines).
fn is_yaml_body(body: &str) -> bool {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?m)^[a-zA-Z][a-zA-Z0-9_.-]*:\s*.+").unwrap());
    let matches = RE.find_iter(body).count();
    matches >= 2
}

/// Returns `true` when the body contains Java properties (key=value or key: value).
fn is_properties_body(body: &str) -> bool {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^[a-z][a-z0-9._-]+=.+").unwrap());
    RE.find_iter(body).count() >= 3
}

/// Returns `true` for Symfony profiler output.
fn is_profiler_page(body: &str) -> bool {
    // Symfony profiler has distinctive markers
    body.contains("sf-toolbar")
        || body.contains("symfony-profiler")
        || body.contains("Symfony Profiler")
        || body.contains("data-symfony-profiler")
        || body.contains("class=\"sf-")
        || body.contains("id=\"sfwdt")
}

/// Returns `true` for phpinfo() output.
fn is_phpinfo(body: &str) -> bool {
    body.contains("phpinfo()") || body.contains("PHP Version") && body.contains("Configure Command")
}

/// Returns `true` when the body contains server-status style output.
fn is_server_status(body: &str) -> bool {
    body.contains("Apache Server Status")
        || body.contains("Server Version:")
        || body.contains("Current Time:")
}

/// Returns `true` when body looks like an actuator endpoint (JSON with expected keys).
fn is_actuator(body: &str) -> bool {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body.trim()) {
        // /actuator returns {"_links": ...}  or individual endpoints return objects
        v.get("_links").is_some()
            || v.get("status").is_some()
            || v.get("beans").is_some()
            || v.get("propertySources").is_some()
            || v.get("activeProfiles").is_some()
            || v.get("contexts").is_some()
            || v.get("traces").is_some()
            || v.get("names").is_some()
    } else {
        false
    }
}

/// Returns `true` for prometheus-style metrics output.
fn is_metrics(body: &str) -> bool {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?m)^(# (HELP|TYPE) |[a-z_]+\{|[a-z_]+ [0-9])").unwrap());
    RE.find_iter(body).count() >= 3
}

/// Returns `true` for debug/pprof style output.
fn is_debug_output(body: &str) -> bool {
    body.contains("goroutine")
        || body.contains("heap profile")
        || body.contains("contention")
        || is_json_body(body)
}

/// Returns `true` for XML config (web.config etc.).
fn is_xml_config(body: &str) -> bool {
    let trimmed = body.trim();
    trimmed.starts_with("<?xml") || trimmed.starts_with("<configuration")
}

/// Returns `true` when JSON body looks like actual config data (not just any JSON).
/// Rejects Android assetlinks, OAuth metadata, and other non-config JSON.
fn is_config_json(body: &str) -> bool {
    let trimmed = body.trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return false;
    }
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(v) => {
            // Reject Android assetlinks arrays
            if let Some(arr) = v.as_array() {
                if let Some(first) = arr.first().and_then(|f| f.as_object()) {
                    if first.contains_key("relation") || first.contains_key("target") {
                        return false;
                    }
                    if let Some(status) = first.get("Status").and_then(|s| s.as_str()) {
                        if status.parse::<u16>().map(|c| c >= 400).unwrap_or(false) {
                            return false;
                        }
                    }
                }
            }
            if let Some(obj) = v.as_object() {
                // Must contain config-like keys
                let config_keys = [
                    "database",
                    "host",
                    "port",
                    "password",
                    "secret",
                    "key",
                    "token",
                    "url",
                    "endpoint",
                    "debug",
                    "environment",
                    "version",
                    "config",
                    "setting",
                ];
                let has_config = obj.keys().any(|k| {
                    let kl = k.to_ascii_lowercase();
                    config_keys.iter().any(|ck| kl.contains(ck))
                });
                // Reject pure error responses
                let has_error = obj.contains_key("errors")
                    && obj.get("data").map(|d| d.is_null()).unwrap_or(false);
                if has_error {
                    return false;
                }
                return has_config;
            }
            false
        }
        Err(_) => false,
    }
}

/// Returns `true` when the body does NOT look like an HTML document.
fn any_non_html(body: &str) -> bool {
    let trimmed = body.trim().to_ascii_lowercase();
    !trimmed.starts_with("<!doctype")
        && !trimmed.starts_with("<html")
        && !trimmed.starts_with("<?xml")
        && !trimmed.contains("<head>")
        && !trimmed.contains("<body")
}

static DEBUG_ENDPOINTS: &[DebugEndpoint] = &[
    DebugEndpoint {
        path: "/debug",
        expected_ct: &[],
        body_validators: &[is_debug_output],
    },
    DebugEndpoint {
        path: "/debug/vars",
        expected_ct: &["application/json"],
        body_validators: &[is_json_body],
    },
    DebugEndpoint {
        path: "/debug/pprof",
        expected_ct: &[],
        body_validators: &[is_debug_output],
    },
    DebugEndpoint {
        path: "/.env",
        expected_ct: &["text/plain", "application/octet-stream"],
        body_validators: &[is_dotenv],
    },
    DebugEndpoint {
        path: "/.env.local",
        expected_ct: &["text/plain", "application/octet-stream"],
        body_validators: &[is_dotenv],
    },
    DebugEndpoint {
        path: "/.env.production",
        expected_ct: &["text/plain", "application/octet-stream"],
        body_validators: &[is_dotenv],
    },
    DebugEndpoint {
        path: "/config.json",
        expected_ct: &["application/json"],
        body_validators: &[is_config_json],
    },
    DebugEndpoint {
        path: "/config.yaml",
        expected_ct: &[
            "text/yaml",
            "application/yaml",
            "text/plain",
            "application/x-yaml",
        ],
        body_validators: &[is_yaml_body],
    },
    DebugEndpoint {
        path: "/config.yml",
        expected_ct: &[
            "text/yaml",
            "application/yaml",
            "text/plain",
            "application/x-yaml",
        ],
        body_validators: &[is_yaml_body],
    },
    DebugEndpoint {
        path: "/settings.json",
        expected_ct: &["application/json"],
        body_validators: &[is_json_body],
    },
    DebugEndpoint {
        path: "/application.properties",
        expected_ct: &["text/plain"],
        body_validators: &[is_properties_body],
    },
    DebugEndpoint {
        path: "/application.yml",
        expected_ct: &[
            "text/yaml",
            "application/yaml",
            "text/plain",
            "application/x-yaml",
        ],
        body_validators: &[is_yaml_body],
    },
    DebugEndpoint {
        path: "/web.config",
        expected_ct: &["text/xml", "application/xml"],
        body_validators: &[is_xml_config],
    },
    DebugEndpoint {
        path: "/phpinfo.php",
        expected_ct: &[],
        body_validators: &[is_phpinfo],
    },
    DebugEndpoint {
        path: "/info.php",
        expected_ct: &[],
        body_validators: &[is_phpinfo],
    },
    DebugEndpoint {
        path: "/server-status",
        expected_ct: &[],
        body_validators: &[is_server_status],
    },
    DebugEndpoint {
        path: "/server-info",
        expected_ct: &[],
        body_validators: &[is_server_status],
    },
    DebugEndpoint {
        path: "/_profiler",
        expected_ct: &["text/html"],
        body_validators: &[is_profiler_page],
    },
    DebugEndpoint {
        path: "/__clockwork",
        expected_ct: &["application/json"],
        body_validators: &[is_json_body],
    },
    DebugEndpoint {
        path: "/actuator",
        expected_ct: &["application/json", "application/vnd.spring-boot.actuator"],
        body_validators: &[is_actuator],
    },
    DebugEndpoint {
        path: "/actuator/env",
        expected_ct: &["application/json", "application/vnd.spring-boot.actuator"],
        body_validators: &[is_actuator],
    },
    DebugEndpoint {
        path: "/actuator/health",
        expected_ct: &["application/json", "application/vnd.spring-boot.actuator"],
        body_validators: &[is_actuator, is_json_body],
    },
    DebugEndpoint {
        path: "/actuator/mappings",
        expected_ct: &["application/json", "application/vnd.spring-boot.actuator"],
        body_validators: &[is_actuator],
    },
    DebugEndpoint {
        path: "/actuator/beans",
        expected_ct: &["application/json", "application/vnd.spring-boot.actuator"],
        body_validators: &[is_actuator],
    },
    DebugEndpoint {
        path: "/actuator/httptrace",
        expected_ct: &["application/json", "application/vnd.spring-boot.actuator"],
        body_validators: &[is_actuator],
    },
    DebugEndpoint {
        path: "/metrics",
        expected_ct: &[
            "text/plain",
            "application/json",
            "application/openmetrics-text",
        ],
        body_validators: &[is_metrics, is_json_body],
    },
    DebugEndpoint {
        path: "/health",
        expected_ct: &["application/json"],
        body_validators: &[is_json_body],
    },
    DebugEndpoint {
        path: "/healthz",
        expected_ct: &["application/json", "text/plain"],
        body_validators: &[is_json_body, any_non_html],
    },
    DebugEndpoint {
        path: "/readyz",
        expected_ct: &["application/json", "text/plain"],
        body_validators: &[is_json_body, any_non_html],
    },
    DebugEndpoint {
        path: "/status",
        expected_ct: &["application/json"],
        body_validators: &[is_json_body],
    },
    DebugEndpoint {
        path: "/admin",
        expected_ct: &[],
        body_validators: &[any_non_html],
    },
    DebugEndpoint {
        path: "/admin/config",
        expected_ct: &["application/json"],
        body_validators: &[is_config_json],
    },
];

// ── SECURITY.TXT paths ────────────────────────────────────────────────────────

static SECURITY_TXT_PATHS: &[&str] = &["/.well-known/security.txt", "/security.txt"];
const BLIND_SSRF_OAST_ENV: &str = "APIHUNTER_OAST_BASE";
const BLIND_SSRF_MAX_PARAMS: usize = 4;
const BLIND_SSRF_PARAM_HINTS: &[&str] = &[
    "url", "uri", "callback", "webhook", "redirect", "next", "dest", "target", "endpoint",
    "avatar", "image", "feed", "proxy",
];
const GATEWAY_HEADER_KEYS: &[&str] = &[
    "x-kong-proxy-latency",
    "x-kong-upstream-latency",
    "x-envoy-upstream-service-time",
    "x-amz-apigw-id",
    "x-amzn-requestid",
    "x-amzn-trace-id",
    "x-azure-ref",
    "cf-ray",
    "x-served-by",
    "x-request-id",
];
const GATEWAY_SERVER_HINTS: &[&str] = &[
    "kong",
    "envoy",
    "apisix",
    "traefik",
    "istio",
    "cloudfront",
    "apigateway",
];

// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl Scanner for ApiSecurityScanner {
    fn name(&self) -> &'static str {
        "api_security"
    }

    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let base = url.trim_end_matches('/');
        let spa_fingerprint = detect_spa_catchall(base, client, &mut errors).await;
        let spa_catchall = spa_fingerprint.is_some();
        let security_txt_host = Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(|h| h.to_ascii_lowercase()));

        // Run all checks; failures are captured rather than propagated.
        check_secrets_in_response(url, client, &mut findings, &mut errors).await;
        check_error_disclosure(url, client, &mut findings, &mut errors).await;
        check_http_methods(url, client, &mut findings, &mut errors, spa_catchall).await;
        check_debug_endpoints(url, client, &mut findings, &mut errors, spa_fingerprint).await;
        check_directory_listing(url, client, &mut findings, &mut errors).await;
        if security_txt_host
            .as_ref()
            .map(|host| self.checked_hosts.insert(host.clone()))
            .unwrap_or(true)
        {
            check_security_txt(url, client, &mut findings).await;
        }
        check_response_headers(url, client, &mut findings, &mut errors).await;
        let gateway_dedupe_key = blind_ssrf_dedupe_key(url).unwrap_or_else(|| format!("raw:{url}"));
        if self.gateway_checked_paths.insert(gateway_dedupe_key) {
            check_api_gateway_signals(url, client, &mut findings, &mut errors).await;
            if config.active_checks {
                check_gateway_bypass_probes(url, client, config, &mut findings, &mut errors).await;
            }
        }

        if config.active_checks {
            check_idor_bola(
                url,
                client,
                self.client_b.as_ref().map(|c| c.as_ref()),
                &mut findings,
                &mut errors,
            )
            .await;
            check_authorization_matrix(
                url,
                client,
                self.client_b.as_ref().map(|c| c.as_ref()),
                &mut findings,
                &mut errors,
            )
            .await;

            let ssrf_dedupe_key =
                blind_ssrf_dedupe_key(url).unwrap_or_else(|| format!("raw:{url}"));
            if self.ssrf_checked_paths.insert(ssrf_dedupe_key) {
                check_blind_ssrf_callback_probe(url, client, config, &mut findings, &mut errors)
                    .await;
            }
        }

        (findings, errors)
    }
}

// ── Helpers: SPA / catch-all detection ─────────────────────────────────────────

/// Returns `true` if the Content-Type looks like HTML.
fn is_html_content_type(ct: &str) -> bool {
    common_is_html_content_type(ct)
}

/// Returns `true` if the Content-Type matches any of the expected types.
fn content_type_matches(ct: &str, expected: &[&str]) -> bool {
    if expected.is_empty() {
        return true; // no constraint
    }
    let lower = ct.to_ascii_lowercase();
    expected.iter().any(|e| lower.contains(e))
}

/// Quick body fingerprint (first 256 bytes + length) — used to detect
/// SPA catch-all that serves the same shell for every route.
fn body_fingerprint(body: &str) -> (usize, u64) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let prefix: String = body.chars().take(256).collect();
    let mut h = DefaultHasher::new();
    prefix.hash(&mut h);
    (body.len(), h.finish())
}

#[derive(Debug, Clone)]
struct IdorResponseSignature {
    body: (usize, u64),
    headers: Vec<(String, String)>,
}

const IDOR_COMPARISON_HEADER_KEYS: &[&str] = &[
    "content-type",
    "content-length",
    "etag",
    "last-modified",
    "cache-control",
    "content-language",
    "vary",
    "location",
    "x-resource-id",
    "x-user-id",
    "x-account-id",
    "x-tenant-id",
    "x-owner-id",
];

const IDOR_COMPARISON_HEADER_PREFIXES: &[&str] = &[
    "x-resource-",
    "x-user-",
    "x-account-",
    "x-tenant-",
    "x-owner-",
];

fn idor_response_signature(response: &HttpResponse) -> IdorResponseSignature {
    let mut headers = response
        .headers
        .iter()
        .filter(|(name, _)| is_idor_comparison_header(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    headers.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    IdorResponseSignature {
        body: body_fingerprint(&response.body),
        headers,
    }
}

fn is_idor_comparison_header(header_name: &str) -> bool {
    IDOR_COMPARISON_HEADER_KEYS.contains(&header_name)
        || IDOR_COMPARISON_HEADER_PREFIXES
            .iter()
            .any(|prefix| header_name.starts_with(prefix))
}

fn idor_match_basis(
    left: &IdorResponseSignature,
    right: &IdorResponseSignature,
) -> Option<&'static str> {
    let body_equal = left.body == right.body;
    let header_equal =
        !left.headers.is_empty() && !right.headers.is_empty() && left.headers == right.headers;

    match (body_equal, header_equal) {
        (true, true) => Some("body+headers"),
        (true, false) => Some("body"),
        (false, true) => Some("headers"),
        (false, false) => None,
    }
}

fn idor_headers_evidence(headers: &[(String, String)]) -> String {
    if headers.is_empty() {
        return "none".to_string();
    }
    headers
        .iter()
        .map(|(name, value)| format!("{name}={}", snippet(value, 96)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Detect SPA catch-all: send a request to a random path that should not exist.
/// If the server returns 200 with HTML (by Content-Type or body inspection),
/// it's very likely a SPA with catch-all routing.
///
/// We test multiple canary paths to handle SPAs that treat paths differently
/// based on prefix (e.g., paths starting with _ vs __ vs random).
async fn detect_spa_catchall(
    base: &str,
    client: &HttpClient,
    errors: &mut Vec<CapturedError>,
) -> Option<(usize, u64)> {
    // Test multiple canary patterns to catch different SPA routing behaviors
    let canaries = [
        format!("{base}/__canary_404_check_xz9q7"),
        format!("{base}/_canary_test_404"),
        format!("{base}/xyzabc123notfound"),
    ];

    for canary in &canaries {
        match client.get(canary).await {
            Ok(resp) if resp.status == 200 => {
                let ct = resp
                    .headers
                    .get("content-type")
                    .map(|s| s.as_str())
                    .unwrap_or("");
                // Detect SPA: either HTML Content-Type OR body actually contains HTML
                let body_is_html = !any_non_html(&resp.body);
                if is_html_content_type(ct) || body_is_html {
                    debug!(
                        url = base,
                        canary = %canary,
                        "SPA catch-all detected (canary returned 200+HTML)"
                    );
                    return Some(body_fingerprint(&resp.body));
                }
            }
            Ok(_) => continue,
            Err(mut e) => {
                e.message = format!("spa_canary_probe: {}", e.message);
                errors.push(e);
                continue;
            }
        }
    }
    None
}

// ── 1. Secrets in response body ───────────────────────────────────────────────

async fn check_secrets_in_response(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let resp = match client.get(url).await {
        Ok(r) => r,
        Err(e) => {
            errors.push(e);
            return;
        }
    };

    // Guard 1: Skip non-200 responses
    if resp.status != 200 {
        return;
    }

    // Guard 2: Skip error responses (403, 404 messages in body)
    let body_lower = resp.body.to_ascii_lowercase();
    if body_lower.contains("403 forbidden")
        || body_lower.contains("404 not found")
        || body_lower.contains("the requested resource is not found")
        || (body_lower.contains("error") && body_lower.contains("status") && resp.body.len() < 500)
    {
        return;
    }

    let ct = resp
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");

    // Guard 3: Distinguish frontend HTML from backend API responses
    let is_html = is_html_content_type(ct);
    let is_js = ct.contains("javascript") || ct.contains("ecmascript");
    let looks_minified = is_js && resp.body.len() > 50000 && !resp.body.contains("\n\n");

    // Guard 4: Check if this is a frontend page (HTML with typical web app markers)
    let is_frontend_page = is_html
        && (body_lower.contains("<!doctype html>")
            || body_lower.contains("<html")
            || body_lower.contains("<head>")
            || body_lower.contains("<body"));

    for chk in SECRET_CHECKS {
        // Skip generic patterns on minified JS
        if looks_minified && matches!(chk.name, "Generic API Key" | "Generic Secret") {
            continue;
        }

        if let Some(m) = chk.re.find(&resp.body) {
            let matched = m.as_str();

            // Additional validation for Generic Secret to avoid false positives
            if chk.name == "Generic Secret" {
                // Extract the value part (after the colon/equals)
                let value_part = matched.rsplit(&[':', '='][..]).next().unwrap_or("");
                let cleaned = value_part.trim().trim_matches(&['"', '\''][..]);

                // Skip if value is empty, whitespace-only, or looks like a placeholder
                if cleaned.is_empty()
                    || cleaned.chars().all(|c| c.is_whitespace())
                    || cleaned.to_lowercase().contains("password")
                    || cleaned.to_lowercase().contains("secret")
                    || cleaned.len() < 12
                {
                    debug!(
                        url = %url,
                        check = chk.name,
                        redacted_match = %redact(matched),
                        "Skipping potential secret match after generic-secret validation"
                    );
                    continue;
                }
            }

            // Guard 5: For Google API keys found in frontend HTML pages,
            // always downgrade to LOW — Google Maps/frontend keys are domain-restricted
            // and never represent backend secret exposure.
            if chk.name == "Google API Key" && is_frontend_page {
                findings.push(
                    Finding::new(
                        url,
                        format!("api_security/secret-in-response/{}", slug(chk.name)),
                        format!("Possible {} in frontend", chk.name),
                        Severity::Low,
                        format!("Possible {} found in frontend HTML. Frontend API keys are typically domain-restricted.", chk.name),
                        "api_security",
                    )
                    .with_evidence(format!(
                        "Pattern: {}\nMatch (redacted): {}\nContext: Frontend HTML\nURL: {url}",
                        chk.name,
                        redact(matched)
                    ))
                    .with_remediation(
                        "Verify this key has proper domain restrictions in your API provider console.",
                    ),
                );
                continue;
            }

            // Guard 6: For Generic API Key in frontend HTML, always downgrade to LOW
            // Frontend pages embed Firebase/analytics keys that are not backend secrets
            if chk.name == "Generic API Key" && is_frontend_page {
                findings.push(
                    Finding::new(
                        url,
                        format!("api_security/secret-in-response/{}", slug(chk.name)),
                        format!("Possible {} in frontend", chk.name),
                        Severity::Low,
                        format!("Possible {} found in frontend HTML. Likely a client-side key.", chk.name),
                        "api_security",
                    )
                    .with_evidence(format!(
                        "Pattern: {}\nMatch (redacted): {}\nContext: Frontend HTML\nURL: {url}",
                        chk.name,
                        redact(matched)
                    ))
                    .with_remediation(
                        "Verify this key is intended for client-side use and has appropriate restrictions.",
                    ),
                );
                continue;
            }

            let redacted = redact(matched);

            findings.push(
                Finding::new(
                    url,
                    format!("api_security/secret-in-response/{}", slug(chk.name)),
                    format!("Possible {} in response", chk.name),
                    Severity::Critical,
                    format!("Possible {} found in HTTP response body.", chk.name),
                    "api_security",
                )
                .with_evidence(format!(
                    "Pattern: {}\nMatch (redacted): {redacted}\nURL: {url}",
                    chk.name
                ))
                .with_remediation(
                    "Remove secrets from responses and rotate exposed credentials immediately.",
                ),
            );
        }
    }
}

// ── 2. Verbose error / debug information ─────────────────────────────────────

async fn check_error_disclosure(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let probe_urls = [format!("{url}/FUZZ_ERROR_XYZ"), format!("{url}?id=_FUZZ_")];

    for probe in &probe_urls {
        let resp = match client.get(probe).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        for chk in ERROR_CHECKS {
            if chk.re.is_match(&resp.body) {
                findings.push(
                    Finding::new(
                        url,
                        format!("api_security/error-disclosure/{}", slug(chk.name)),
                        format!("Error disclosure: {}", chk.name),
                        Severity::Medium,
                        format!(
                            "Verbose error information leaked: {} detected in response \
                         to malformed request.",
                            chk.name
                        ),
                        "api_security",
                    )
                    .with_evidence(format!(
                        "Probe URL: {probe}\nStatus: {}\nSnippet: {}",
                        resp.status,
                        snippet(&resp.body, 400)
                    ))
                    .with_remediation(
                        "Disable verbose error pages in production and return generic errors.",
                    ),
                );
                break;
            }
        }
    }
}

// ── 3. HTTP method enumeration ────────────────────────────────────────────────

async fn check_http_methods(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
    spa_catchall: bool,
) {
    if spa_catchall {
        debug!(url = %url, "SPA catch-all detected; skipping method probing");
    }

    // First try OPTIONS — it may advertise allowed methods directly.
    let allowed_from_options = match client.options(url, None).await {
        Ok(resp) => {
            let from_allow = resp.headers.get("allow").cloned().unwrap_or_default();

            let from_acam = resp
                .headers
                .get("access-control-allow-methods")
                .cloned()
                .unwrap_or_default();

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
        let advertised = allowed_from_options.iter().any(|m| m == method);

        let actually_allowed = if advertised {
            true
        } else if spa_catchall {
            false
        } else {
            match client.method_probe(method, url).await {
                Ok(r) => r.status < 405,
                Err(e) => {
                    errors.push(e);
                    false
                }
            }
        };

        if actually_allowed {
            dangerous_allowed.push(method.to_string());
        }
    }

    if dangerous_allowed.contains(&"TRACE".to_string()) {
        findings.push(
            Finding::new(
                url,
                "api_security/http-method/trace-enabled",
                "HTTP TRACE enabled",
                Severity::Low,
                "HTTP TRACE method is enabled. Combined with client-side bugs it can \
             enable Cross-Site Tracing (XST) attacks.",
                "api_security",
            )
            .with_evidence(format!("TRACE responded with status < 405 on {url}"))
            .with_remediation("Disable TRACE at the web server or reverse proxy configuration."),
        );
    }

    let write_methods: Vec<&str> = dangerous_allowed
        .iter()
        .filter(|m| matches!(m.as_str(), "PUT" | "DELETE" | "PATCH"))
        .map(String::as_str)
        .collect();

    if !write_methods.is_empty() {
        findings.push(Finding::new(
            url,
            "api_security/http-method/write-methods-enabled",
            "Write HTTP methods enabled",
            Severity::Medium,
            format!(
                "Write HTTP methods accepted: {}. Verify these require authentication \
                 and are not accessible to unauthenticated clients.",
                write_methods.join(", ")
            ),
            "api_security",
        )
        .with_evidence(format!(
            "Methods returning non-405 on {url}: {}",
            write_methods.join(", ")
        ))
        .with_remediation(
            "Require authentication/authorization for write methods and disable them when unused.",
        ));
    }
}

// ── 4. Debug / admin endpoint exposure ───────────────────────────────────────

async fn check_debug_endpoints(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
    spa_fingerprint: Option<(usize, u64)>,
) {
    let base = url.trim_end_matches('/');
    let mut endpoints = DEBUG_ENDPOINTS.iter().collect::<Vec<_>>();
    {
        let mut rng = rand::thread_rng();
        endpoints.shuffle(&mut rng);
    }

    let critical_keywords = ["env", "config", "secret", "password", "credential", "key"];
    let high_keywords = ["actuator", "pprof", "phpinfo", "profiler", "clockwork"];

    for ep in endpoints {
        let probe = format!("{base}{}", ep.path);
        let resp = match client.get(&probe).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        // ── Guard 1: must be 200 ─────────────────────────────────────────────
        if resp.status != 200 {
            continue;
        }

        let ct = resp
            .headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");

        // ── Guard 2: SPA catch-all — if we detected one and this response
        //    matches the fingerprint (regardless of Content-Type), skip it. ───
        if let Some(spa_fp) = &spa_fingerprint {
            let resp_fp = body_fingerprint(&resp.body);
            // Same length ±20% and same prefix hash → SPA shell
            // Increased tolerance to catch SPAs that inject slightly different content
            let len_ratio = resp_fp.0 as f64 / spa_fp.0.max(1) as f64;
            if (0.80..=1.20).contains(&len_ratio) && resp_fp.1 == spa_fp.1 {
                debug!(
                    url = %probe,
                    "Skipping — matches SPA catch-all fingerprint"
                );
                continue;
            }

            // Additional check: if both are HTML and similar size, likely same SPA shell
            let ct = resp
                .headers
                .get("content-type")
                .map(|s| s.as_str())
                .unwrap_or("");
            if is_html_content_type(ct) && (0.70..=1.30).contains(&len_ratio) {
                debug!(
                    url = %probe,
                    "Skipping — HTML response with similar size to SPA shell"
                );
                continue;
            }
        }

        // ── Guard 3: Content-Type validation ─────────────────────────────────
        // If we have expected content-types, check them.
        // Any HTML response for config/env endpoints is almost certainly a
        // custom error page or SPA rather than real leaked config.
        if !ep.expected_ct.is_empty() && !content_type_matches(ct, ep.expected_ct) {
            // HTML response for a config/env endpoint → false positive
            if is_html_content_type(ct) {
                debug!(
                    url = %probe,
                    ct,
                    "Skipping — HTML response for non-HTML endpoint"
                );
                continue;
            }
        }

        // ── Guard 4: Body content validation ─────────────────────────────────
        // The response body must pass at least one validator.
        if !ep.body_validators.is_empty() {
            let passes = ep.body_validators.iter().any(|v| v(&resp.body));
            if !passes {
                debug!(
                    url = %probe,
                    "Skipping — body content does not match expected patterns"
                );
                continue;
            }
        }

        // ── All guards passed — emit finding ─────────────────────────────────
        let lower_path = ep.path.to_ascii_lowercase();

        let severity = if critical_keywords.iter().any(|k| lower_path.contains(k)) {
            Severity::Critical
        } else if high_keywords.iter().any(|k| lower_path.contains(k)) {
            Severity::High
        } else {
            Severity::Medium
        };

        findings.push(
            Finding::new(
                url,
                format!("api_security/debug-endpoint{}", ep.path.replace('/', "-")),
                format!("Debug endpoint exposed: {}", ep.path),
                severity,
                format!(
                    "Debug/admin endpoint publicly accessible: {}. \
                 This may expose internal configuration, metrics, or runtime data.",
                    ep.path
                ),
                "api_security",
            )
            .with_evidence(format!(
                "URL: {probe}\nStatus: 200\nContent-Type: {ct}\nBody snippet:\n{}",
                snippet(&resp.body, 500)
            ))
            .with_remediation(
                "Restrict debug/admin endpoints to internal networks or require authentication.",
            ),
        );
    }
}

// ── 5. Directory listing ───────────────────────────────────────────────────────

async fn check_directory_listing(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let mut probe_paths = vec!["/", "/static/", "/assets/", "/uploads/", "/files/"];
    {
        let mut rng = rand::thread_rng();
        probe_paths.shuffle(&mut rng);
    }
    let base = url.trim_end_matches('/');

    for path in probe_paths {
        let probe = format!("{base}{path}");
        let resp = match client.get(&probe).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        if resp.status != 200 {
            continue;
        }

        // Guard: Content-Type should be HTML for a directory listing page
        let ct = resp
            .headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !ct.is_empty() && !is_html_content_type(ct) && !ct.contains("text/plain") {
            continue;
        }

        let body_lower = resp.body.to_ascii_lowercase();
        let matched_marker = DIR_LISTING_MARKERS
            .iter()
            .find(|&&m| body_lower.contains(&m.to_ascii_lowercase()));

        if let Some(marker) = matched_marker {
            findings.push(
                Finding::new(
                    url,
                    format!(
                        "api_security/directory-listing{}",
                        path.trim_end_matches('/').replace('/', "-")
                    ),
                    format!("Directory listing at {path}"),
                    Severity::Medium,
                    format!(
                        "Directory listing enabled at `{path}`. \
                     Attackers can enumerate files and discover sensitive assets."
                    ),
                    "api_security",
                )
                .with_evidence(format!(
                    "URL: {probe}\nMatched marker: \"{marker}\"\nSnippet:\n{}",
                    snippet(&resp.body, 400)
                ))
                .with_remediation(
                    "Disable directory listing in the web server and restrict public file access.",
                ),
            );
        }
    }
}

// ── 6. security.txt presence ──────────────────────────────────────────────────

async fn check_security_txt(url: &str, client: &HttpClient, findings: &mut Vec<Finding>) {
    let base = url.trim_end_matches('/');
    let mut found = false;

    for path in SECURITY_TXT_PATHS {
        let probe = format!("{base}{path}");
        if let Ok(resp) = client.get(&probe).await {
            if resp.status == 200 {
                let ct = resp
                    .headers
                    .get("content-type")
                    .map(|s| s.as_str())
                    .unwrap_or("");
                // Genuine security.txt should be text/plain and contain "Contact:"
                if !is_html_content_type(ct) && resp.body.to_ascii_lowercase().contains("contact:")
                {
                    found = true;
                    break;
                }
            }
        }
    }

    if !found {
        findings.push(Finding::new(
            url,
            "api_security/security-txt/missing",
            "Missing security.txt",
            Severity::Info,
            "No valid security.txt found at /.well-known/security.txt or /security.txt. \
             RFC 9116 recommends publishing one so researchers can report vulnerabilities.",
            "api_security",
        ).with_remediation(
            "Publish a security.txt with contact and policy details under /.well-known/security.txt.",
        ));
    }
}

// ── 7. Response-header security checks ───────────────────────────────────────

struct HeaderCheck {
    name: &'static str,
    slug: &'static str,
    detail: &'static str,
    severity: Severity,
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

static VERSION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d+\.\d+").unwrap());

async fn check_response_headers(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let resp = match client.get(url).await {
        Ok(r) => r,
        Err(e) => {
            errors.push(e);
            return;
        }
    };

    let headers: HashMap<String, String> = resp
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();

    for check in HEADER_CHECKS {
        let key = check.name;
        let value = headers.get(key);

        match key {
            "x-powered-by" => {
                if value.is_some() {
                    findings.push(header_finding(url, check, value));
                }
            }
            "server" => {
                if let Some(v) = value {
                    if VERSION_RE.is_match(v) {
                        findings.push(header_finding(url, check, Some(v)));
                    }
                }
            }
            _ => match value {
                None => {
                    findings.push(header_finding(url, check, None));
                }
                Some(v) => {
                    if let Some(required) = check.must_contain {
                        if !v.to_ascii_lowercase().contains(required) {
                            findings.push(
                                Finding::new(
                                    url,
                                    format!("api_security/headers/{}-weak", check.slug),
                                    format!("{} present but weak", check.name),
                                    check.severity.clone(),
                                    format!(
                                        "{} present but value does not contain `{required}`.",
                                        check.name
                                    ),
                                    "api_security",
                                )
                                .with_evidence(format!("{}: {v}", check.name))
                                .with_remediation(header_remediation(check)),
                            );
                        }
                    }
                }
            },
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn header_finding(url: &str, check: &HeaderCheck, value: Option<&String>) -> Finding {
    Finding::new(
        url,
        format!("api_security/headers/{}", check.slug),
        check.detail,
        check.severity.clone(),
        check.detail,
        "api_security",
    )
    .with_evidence(
        value
            .map(|v| format!("{}: {v}", check.name))
            .unwrap_or_default(),
    )
    .with_remediation(header_remediation(check))
}

fn header_remediation(check: &HeaderCheck) -> &'static str {
    match check.slug {
        "hsts-missing" =>
            "Enable HSTS (Strict-Transport-Security) with a long max-age and includeSubDomains.",
        "xcto-missing" =>
            "Set X-Content-Type-Options: nosniff.",
        "xfo-missing" =>
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors.",
        "referrer-policy-missing" =>
            "Set Referrer-Policy to a restrictive value such as no-referrer or strict-origin-when-cross-origin.",
        "permissions-policy-missing" =>
            "Set Permissions-Policy to disable unused browser features.",
        "x-powered-by-present" =>
            "Remove X-Powered-By to reduce stack fingerprinting.",
        "server-version-leaked" =>
            "Remove or genericize the Server header to reduce fingerprinting.",
        _ =>
            "Harden response headers according to your security baseline.",
    }
}

fn redact(s: &str) -> String {
    redact_secret(s, 4)
}

fn slug(s: &str) -> String {
    slugify(s)
}

fn snippet(s: &str, max_len: usize) -> String {
    shared_snippet(s, max_len)
}

// ── Active checks (opt-in) ────────────────────────────────────────────────────

async fn check_api_gateway_signals(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let baseline = match client.get(url).await {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return;
        }
    };

    let mut evidence = Vec::new();
    for key in GATEWAY_HEADER_KEYS {
        if let Some(value) = baseline.header(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                evidence.push(format!("{key}: {trimmed}"));
            }
        }
    }

    if let Some(server) = baseline.header("server") {
        let lower = server.to_ascii_lowercase();
        if GATEWAY_SERVER_HINTS.iter().any(|hint| lower.contains(hint)) {
            evidence.push(format!("server: {server}"));
        }
    }

    if evidence.is_empty() {
        return;
    }

    findings.push(
        Finding::new(
            url,
            "api_security/gateway-detected",
            "API gateway/reverse-proxy signal detected",
            Severity::Info,
            "Response metadata suggests requests are passing through an API gateway or edge proxy layer.",
            "api_security",
        )
        .with_evidence(evidence.join(" | "))
        .with_confidence(Confidence::Low)
        .with_remediation(
            "Review gateway policy order (authn/authz/rate-limit/routing) and ensure security controls are enforced before upstream routing.",
        ),
    );
}

async fn check_gateway_bypass_probes(
    url: &str,
    client: &HttpClient,
    config: &Config,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let parsed = match Url::parse(url) {
        Ok(value) => value,
        Err(error) => {
            errors.push(CapturedError::parse(
                "api_security/gateway-bypass-url-parse",
                error.to_string(),
            ));
            return;
        }
    };

    let baseline = match client.get(url).await {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return;
        }
    };

    if !matches!(baseline.status, 401 | 403 | 404 | 405) {
        return;
    }

    let path = parsed.path();
    let host = parsed.host_str().unwrap_or_default().to_string();
    let probes = gateway_bypass_probe_headers(path, &host);

    if config.dry_run {
        findings.push(
            Finding::new(
                url,
                "api_security/gateway-bypass-dry-run",
                "Gateway bypass probes planned (dry run)",
                Severity::Info,
                "Gateway normalization/bypass probes were skipped because --dry-run is enabled.",
                "api_security",
            )
            .with_evidence(format!(
                "Baseline status: {}\nHeaders: {}",
                baseline.status,
                probes
                    .iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .with_confidence(Confidence::Low)
            .with_metadata(serde_json::json!({
                "sequence_confirmed": false,
                "confirmation_depth": 0,
            }))
            .with_remediation(
                "Run without --dry-run in an authorized test window to execute gateway bypass probes.",
            ),
        );
        return;
    }

    let mut bypass_hits = Vec::new();
    for (header_name, value) in probes {
        let headers = single_probe_header_map(header_name, &value);
        let response = match client.request(Method::GET, url, Some(headers), None).await {
            Ok(value) => value,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };

        if response.status < 400 && baseline.status >= 400 {
            bypass_hits.push((header_name.to_string(), value, response.status));
        }
    }

    if bypass_hits.is_empty() {
        return;
    }

    findings.push(
        Finding::new(
            url,
            "api_security/gateway-bypass-suspected",
            "Gateway bypass behavior suspected",
            if bypass_hits.iter().any(|(_, _, status)| *status < 300) {
                Severity::High
            } else {
                Severity::Medium
            },
            "Gateway-oriented normalization headers changed a blocked response into an allowed one. This can indicate route/auth policy bypass through edge header trust.",
            "api_security",
        )
        .with_evidence(format!(
            "Baseline status: {}\nProbe statuses:\n{}",
            baseline.status,
            bypass_hits
                .iter()
                .map(|(name, value, status)| format!("  {name}={value} -> HTTP {status}"))
                .collect::<Vec<_>>()
                .join("\n")
        ))
        .with_confidence(if matches!(baseline.status, 401 | 403) {
            Confidence::High
        } else {
            Confidence::Medium
        })
        .with_metadata(serde_json::json!({
            "sequence_confirmed": true,
            "confirmation_depth": 1,
            "baseline_status": baseline.status,
            "probe_count": bypass_hits.len(),
        }))
        .with_remediation(
            "Disable trust for client-supplied routing override headers at the edge and enforce authorization before path rewrites or upstream forwarding.",
        ),
    );
}

fn gateway_bypass_probe_headers(path: &str, host: &str) -> Vec<(&'static str, String)> {
    vec![
        ("X-Original-URL", path.to_string()),
        ("X-Rewrite-URL", path.to_string()),
        ("X-Forwarded-Prefix", "/".to_string()),
        ("X-Forwarded-Host", host.to_string()),
        ("X-Forwarded-Uri", path.to_string()),
    ]
}

fn single_probe_header_map(name: &str, value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let (Ok(key), Ok(val)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(key, val);
    }
    headers
}

async fn check_blind_ssrf_callback_probe(
    url: &str,
    client: &HttpClient,
    config: &Config,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let Some(oast_base) = std::env::var(BLIND_SSRF_OAST_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    let parsed = match Url::parse(url) {
        Ok(value) => value,
        Err(error) => {
            errors.push(CapturedError::parse(
                "api_security/blind-ssrf-url-parse",
                error.to_string(),
            ));
            return;
        }
    };

    let candidate_params = select_blind_ssrf_params(&parsed);
    if candidate_params.is_empty() {
        return;
    }

    let mut probes = Vec::new();
    let mut reflected_params = Vec::new();

    for (index, param_name) in candidate_params.iter().enumerate() {
        let token = build_blind_ssrf_token(&parsed, param_name, index);
        let callback = format!("{}/{}", oast_base.trim_end_matches('/'), token);
        let probe_url = with_query_param(&parsed, param_name, &callback);

        if config.dry_run {
            probes.push(format!("{param_name} -> {callback} [planned]"));
            continue;
        }

        let response = match client.get(probe_url.as_str()).await {
            Ok(value) => value,
            Err(mut error) => {
                error.message = format!("blind_ssrf_probe[{param_name}]: {}", error.message);
                errors.push(error);
                continue;
            }
        };

        let reflected = response_reflects_callback_signal(&response, &token, &oast_base);
        probes.push(format!(
            "{param_name} -> HTTP {} ({})",
            response.status,
            if reflected { "reflected" } else { "dispatched" }
        ));
        if reflected {
            reflected_params.push(param_name.clone());
        }
    }

    if probes.is_empty() {
        return;
    }

    if config.dry_run {
        findings.push(
            Finding::new(
                url,
                "api_security/blind-ssrf-probe-dry-run",
                "Blind SSRF callback probes planned (dry run)",
                Severity::Info,
                "Blind SSRF callback probes were skipped because --dry-run is enabled.",
                "api_security",
            )
            .with_evidence(format!(
                "Env: {BLIND_SSRF_OAST_ENV}\nProbe plan:\n{}",
                probes.join("\n")
            ))
            .with_confidence(Confidence::Low)
            .with_metadata(serde_json::json!({
                "sequence_confirmed": false,
                "confirmation_depth": 0,
                "probe_count": probes.len(),
                "env": BLIND_SSRF_OAST_ENV,
            }))
            .with_remediation(
                "Run without --dry-run and monitor your OAST listener for callback hits.",
            ),
        );
        return;
    }

    let reflected = !reflected_params.is_empty();
    findings.push(
        Finding::new(
            url,
            if reflected {
                "api_security/blind-ssrf-token-reflected"
            } else {
                "api_security/blind-ssrf-probe-dispatched"
            },
            if reflected {
                "Blind SSRF callback token reflected in response"
            } else {
                "Blind SSRF callback probes dispatched"
            },
            if reflected {
                Severity::Medium
            } else {
                Severity::Info
            },
            if reflected {
                "The callback token/domain appeared in immediate responses after callback-parameter probes. This can indicate unsafe callback URL handling."
            } else {
                "Callback-style query-parameter probes were dispatched for blind SSRF detection. Check your OAST listener for outbound hits."
            },
            "api_security",
        )
        .with_evidence(format!(
            "Env: {BLIND_SSRF_OAST_ENV}\nProbe results:\n{}",
            probes.join("\n")
        ))
        .with_confidence(if reflected {
            Confidence::Medium
        } else {
            Confidence::Low
        })
        .with_metadata(serde_json::json!({
            "sequence_confirmed": reflected,
            "confirmation_depth": if reflected { 2 } else { 1 },
            "probe_count": probes.len(),
            "reflected_params": reflected_params,
            "env": BLIND_SSRF_OAST_ENV,
        }))
        .with_remediation(
            "Block unrestricted backend egress, enforce callback URL allowlists, and validate/normalize user-controlled URL parameters before fetch/forward operations.",
        ),
    );
}

fn blind_ssrf_dedupe_key(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "0".to_string());
    Some(format!("{host}:{port}{}", parsed.path()))
}

fn select_blind_ssrf_params(parsed: &Url) -> Vec<String> {
    let mut selected = Vec::new();
    let mut seen = HashSet::new();

    for (name, _) in parsed.query_pairs() {
        let lower = name.to_ascii_lowercase();
        if !is_blind_ssrf_candidate_param(&lower) || !seen.insert(lower) {
            continue;
        }
        selected.push(name.into_owned());
        if selected.len() >= BLIND_SSRF_MAX_PARAMS {
            return selected;
        }
    }

    for param in BLIND_SSRF_PARAM_HINTS {
        let lower = param.to_ascii_lowercase();
        if !seen.insert(lower) {
            continue;
        }
        selected.push((*param).to_string());
        if selected.len() >= BLIND_SSRF_MAX_PARAMS {
            break;
        }
    }

    selected
}

fn is_blind_ssrf_candidate_param(param: &str) -> bool {
    let lower = param.to_ascii_lowercase();
    BLIND_SSRF_PARAM_HINTS
        .iter()
        .any(|candidate| lower == *candidate || lower.contains(candidate))
}

fn build_blind_ssrf_token(url: &Url, param_name: &str, index: usize) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let host = url
        .host_str()
        .unwrap_or("host")
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(10)
        .collect::<String>()
        .to_ascii_lowercase();
    let path = url
        .path()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(10)
        .collect::<String>()
        .to_ascii_lowercase();
    let param = param_name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("apihunter-ssrf-{host}-{path}-{param}-{index}-{millis}")
}

fn with_query_param(url: &Url, param_name: &str, value: &str) -> Url {
    let mut next = url.clone();
    let mut pairs = Vec::new();
    let mut replaced = false;
    for (name, current_value) in url.query_pairs() {
        if name.eq_ignore_ascii_case(param_name) {
            if !replaced {
                pairs.push((name.to_string(), value.to_string()));
                replaced = true;
            }
        } else {
            pairs.push((name.to_string(), current_value.to_string()));
        }
    }
    if !replaced {
        pairs.push((param_name.to_string(), value.to_string()));
    }

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, current_value) in &pairs {
        serializer.append_pair(name, current_value);
    }
    let query = serializer.finish();
    next.set_query(Some(&query));
    next
}

fn response_reflects_callback_signal(
    response: &HttpResponse,
    token: &str,
    oast_base: &str,
) -> bool {
    let oast_lower = oast_base.to_ascii_lowercase();
    if response.body.contains(token) || response.body.to_ascii_lowercase().contains(&oast_lower) {
        return true;
    }
    response
        .headers
        .values()
        .any(|value| value.contains(token) || value.to_ascii_lowercase().contains(&oast_lower))
}

// ── IDOR / BOLA detection ─────────────────────────────────────────────────────
//
// Three tiers, each independently useful:
//
// Tier 1 — Unauthenticated comparison
//   The same URL is fetched without credentials. If it returns a 200 with
//   different content than the authenticated response, the endpoint may be
//   publicly accessible when it shouldn't be.
//
// Tier 2 — ID range walk
//   Walk a small window of IDs around the one in the URL. Track which return
//   200 and which return 403/404. A pattern like [200, 200, 200, 403, 403]
//   for consecutive IDs suggests authorization is not object-specific.
//
// Tier 3 — Cross-user comparison (requires client_b)
//   Fetch the URL with a second identity. If the second identity gets the
//   same content as the first, object-level authorization is missing.

async fn check_idor_bola(
    url: &str,
    client: &HttpClient,
    client_b: Option<&HttpClient>,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    // Only run on URLs with numeric path segments
    let numeric_seg = match find_numeric_segment(url) {
        Some(s) => s,
        None => return,
    };

    // ── Tier 1: Unauthenticated comparison ────────────────────────────────────

    let mut steps = vec![
        SequenceStep::new("authed-primary", SequenceActor::Primary, Method::GET, url),
        SequenceStep::new(
            "unauthenticated-primary",
            SequenceActor::Unauthenticated,
            Method::GET,
            url,
        ),
    ];
    if client_b.is_some() {
        steps.push(SequenceStep::new(
            "authed-secondary",
            SequenceActor::Secondary,
            Method::GET,
            url,
        ));
    }

    let (sequence_results, mut sequence_errors) =
        SequenceRunner::new(client, client_b).run(&steps).await;
    errors.append(&mut sequence_errors);

    let authed_resp = match sequence_response(&sequence_results, "authed-primary") {
        Some(r) => r,
        None => return,
    };

    if authed_resp.status >= 400 {
        return; // Not a live endpoint with our credentials
    }

    let unauth_resp = match sequence_response(&sequence_results, "unauthenticated-primary") {
        Some(r) => r,
        None => return,
    };

    let authed_sig = idor_response_signature(&authed_resp);

    match unauth_resp.status {
        200..=299 => {
            let unauth_sig = idor_response_signature(&unauth_resp);
            if let Some(match_basis) = idor_match_basis(&authed_sig, &unauth_sig) {
                // Same content unauthenticated — endpoint is public (may be intentional)
                findings.push(
                    Finding::new(
                        url,
                        "api_security/unauthenticated-access",
                        "Endpoint accessible without authentication",
                        Severity::Medium,
                        "Endpoint returns the same response with and without auth credentials. \
                         If this resource should be protected, authentication is not enforced.",
                        "api_security",
                    )
                    .with_evidence(format!(
                        "Authed: HTTP {}, Unauthed: HTTP {}\n\
                         Comparison basis: {match_basis}\n\
                         Authed body hash: {:x}, Unauthed body hash: {:x}\n\
                         Authed compare headers: {}\n\
                         Unauthed compare headers: {}",
                        authed_resp.status,
                        unauth_resp.status,
                        authed_sig.body.1,
                        unauth_sig.body.1,
                        idor_headers_evidence(&authed_sig.headers),
                        idor_headers_evidence(&unauth_sig.headers),
                    ))
                    .with_confidence(Confidence::Medium)
                    .with_remediation(
                        "Enforce authentication middleware on all protected endpoints.",
                    ),
                );
            } else {
                // Different content unauthenticated — endpoint is accessible but
                // returns different data. Could be IDOR or partial access.
                findings.push(
                    Finding::new(
                        url,
                        "api_security/partial-unauth-access",
                        "Endpoint returns data without authentication",
                        Severity::High,
                        "Endpoint returns a successful response without credentials but \
                         with different content than the authenticated response. \
                         The unauthenticated response may contain another user's data.",
                        "api_security",
                    )
                    .with_evidence(format!(
                        "Authed status: {}, Unauthed status: {}\n\
                         Authed body hash: {:x}, Unauthed body hash: {:x}\n\
                         Authed compare headers: {}\n\
                         Unauthed compare headers: {}",
                        authed_resp.status,
                        unauth_resp.status,
                        authed_sig.body.1,
                        unauth_sig.body.1,
                        idor_headers_evidence(&authed_sig.headers),
                        idor_headers_evidence(&unauth_sig.headers),
                    ))
                    .with_confidence(Confidence::High)
                    .with_remediation(
                        "Verify object-level authorization is enforced for every identity, \
                         including unauthenticated requests.",
                    ),
                );
            }
        }
        401 | 403 => {
            // Auth is being enforced — good. Continue to tier 2.
        }
        _ => {
            // Unusual status — skip
        }
    }

    // ── Tier 2: ID range walk ─────────────────────────────────────────────────
    //
    // Walk IDs [base-2, base-1, base, base+1, base+2].
    // Collect (id, status, body_fp) tuples.
    // Finding: if IDs outside the original all return 200, authorization
    // may be missing per-object (returns data for any ID).

    type RangeResult = (u64, Option<u16>, Option<(usize, u64)>);

    let base_id = numeric_seg.value;
    let range_ids: Vec<u64> = (base_id.saturating_sub(2)..=base_id + 2).collect();

    let mut range_results: Vec<RangeResult> = Vec::new();

    for &id in &range_ids {
        let probe_url = replace_numeric_segment(url, &numeric_seg, id);
        match client.get(&probe_url).await {
            Ok(r) => {
                let fp = if r.status < 400 {
                    Some(body_fingerprint(&r.body))
                } else {
                    None
                };
                range_results.push((id, Some(r.status), fp));
            }
            Err(e) => {
                errors.push(e);
                range_results.push((id, None, None));
            }
        }
    }

    // Count how many IDs outside the original return 200 with real content
    let other_successes: Vec<&RangeResult> = range_results
        .iter()
        .filter(|(id, status, fp)| {
            *id != base_id
                && status
                    .map(|status| (200..400).contains(&status))
                    .unwrap_or(false)
                && fp.as_ref().map(|f| f.0 > 32).unwrap_or(false)
            // non-trivial body
        })
        .collect();

    let other_success_count = other_successes.len();
    if other_success_count >= 2 {
        let severity = idor_range_walk_severity(other_success_count);

        // At least 2 adjacent IDs return valid data — likely no per-object auth
        let evidence_lines: Vec<String> = range_results
            .iter()
            .map(|(id, status, _)| {
                let marker = if *id == base_id { " ← original" } else { "" };
                let status_display = status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "ERROR".to_string());
                format!("  ID {id}: HTTP {status_display}{marker}")
            })
            .collect();

        findings.push(
            Finding::new(
                url,
                "api_security/idor-id-enumerable",
                "Object IDs appear enumerable (IDOR/BOLA)",
                severity,
                format!(
                    "{} adjacent IDs near the original resource returned successful responses. \
                     Object-level authorization may not be enforced per resource — \
                     any authenticated user may be able to access other users' objects.",
                    other_success_count
                ),
                "api_security",
            )
            .with_evidence(format!(
                "ID range probe results:\n{}",
                evidence_lines.join("\n")
            ))
            .with_confidence(match other_success_count {
                0..=2 => Confidence::Medium,
                _ => Confidence::High,
            })
            .with_remediation(
                "Enforce object-level authorization (BOLA) checks: verify the requesting \
                 identity owns or has explicit access to each requested resource ID.",
            ),
        );
    }

    // ── Tier 3: Cross-user comparison ─────────────────────────────────────────

    let Some(_client_b) = client_b else {
        return;
    };

    let resp_b = match sequence_response(&sequence_results, "authed-secondary") {
        Some(r) => r,
        None => return,
    };

    // Both identities must get a 200 for this to be meaningful
    if resp_b.status >= 400 {
        return;
    }

    let resp_b_sig = idor_response_signature(&resp_b);

    if let Some(match_basis) = idor_match_basis(&authed_sig, &resp_b_sig) {
        // Both users get identical responses — user B can see user A's data
        findings.push(
            Finding::new(
                url,
                "api_security/idor-cross-user",
                "IDOR: second identity accesses same object (BOLA confirmed)",
                Severity::Critical,
                "Two different identities received identical responses for the same resource. \
                 This confirms broken object-level authorization — a user can access \
                 another user's resources using their own valid credentials.",
                "api_security",
            )
            .with_evidence(format!(
                "Identity A: HTTP {}, body hash {:x}\n\
                 Identity B: HTTP {}, body hash {:x}\n\
                 Comparison basis: {match_basis}\n\
                 Identity A compare headers: {}\n\
                 Identity B compare headers: {}",
                authed_resp.status,
                authed_sig.body.1,
                resp_b.status,
                resp_b_sig.body.1,
                idor_headers_evidence(&authed_sig.headers),
                idor_headers_evidence(&resp_b_sig.headers),
            ))
            .with_confidence(Confidence::High)
            .with_remediation(
                "Enforce strict object-level authorization. Every resource access must \
                 verify the requesting identity's ownership or explicit permission for \
                 that specific object — never rely solely on global authentication.",
            ),
        );
    }
}

async fn check_authorization_matrix(
    url: &str,
    client: &HttpClient,
    client_b: Option<&HttpClient>,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    if find_numeric_segment(url).is_some() {
        // Numeric-resource paths are already handled by dedicated IDOR/BOLA checks.
        return;
    }
    if !is_sensitive_resource_path(url) {
        return;
    }

    let mut steps = vec![
        SequenceStep::new(
            "matrix-authed-primary",
            SequenceActor::Primary,
            Method::GET,
            url,
        ),
        SequenceStep::new(
            "matrix-unauthenticated-primary",
            SequenceActor::Unauthenticated,
            Method::GET,
            url,
        ),
    ];
    if client_b.is_some() {
        steps.push(SequenceStep::new(
            "matrix-authed-secondary",
            SequenceActor::Secondary,
            Method::GET,
            url,
        ));
    }

    let (results, mut seq_errors) = SequenceRunner::new(client, client_b).run(&steps).await;
    errors.append(&mut seq_errors);

    let Some(authed_primary) = sequence_response(&results, "matrix-authed-primary") else {
        return;
    };
    if authed_primary.status >= 400 {
        return;
    }

    let Some(unauth_primary) = sequence_response(&results, "matrix-unauthenticated-primary") else {
        return;
    };
    let authed_sig = idor_response_signature(&authed_primary);
    let unauth_same_basis = if (200..400).contains(&unauth_primary.status) {
        let unauth_sig = idor_response_signature(&unauth_primary);
        idor_match_basis(&authed_sig, &unauth_sig)
    } else {
        None
    };
    let unauth_same = unauth_same_basis.is_some();

    let secondary_same_basis = sequence_response(&results, "matrix-authed-secondary")
        .filter(|resp| (200..400).contains(&resp.status))
        .and_then(|resp| {
            let secondary_sig = idor_response_signature(&resp);
            idor_match_basis(&authed_sig, &secondary_sig)
        });
    let secondary_same = secondary_same_basis.is_some();

    let confirmation_depth = usize::from(unauth_same) + usize::from(secondary_same);
    if confirmation_depth == 0 {
        return;
    }

    let (check, title, severity, detail) = match (unauth_same, secondary_same) {
        (true, true) => (
            "api_security/authz-matrix-broken",
            "Authorization matrix bypass: public + cross-identity exposure",
            Severity::Critical,
            "Both unauthenticated and secondary-identity requests returned the same resource representation as the primary identity. This strongly indicates broken authorization boundaries.",
        ),
        (false, true) => (
            "api_security/authz-matrix-cross-identity",
            "Authorization matrix bypass: cross-identity exposure",
            Severity::High,
            "A second authenticated identity received the same resource representation as the primary identity. This indicates missing object-level authorization checks.",
        ),
        (true, false) => (
            "api_security/authz-matrix-public",
            "Authorization matrix weakness: sensitive endpoint behaves as public",
            Severity::High,
            "A sensitive endpoint returned the same resource representation with and without authentication. This suggests missing authentication/authorization enforcement.",
        ),
        (false, false) => return,
    };

    findings.push(
        Finding::new(url, check, title, severity, detail, "api_security")
            .with_evidence(format!(
                "primary_authed={} unauthenticated={} secondary={}\n\
                 comparison_basis_unauth={} comparison_basis_secondary={}",
                authed_primary.status,
                unauth_primary.status,
                sequence_response(&results, "matrix-authed-secondary")
                    .map(|resp| resp.status.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                unauth_same_basis.unwrap_or("none"),
                secondary_same_basis.unwrap_or("none"),
            ))
            .with_confidence(if secondary_same {
                Confidence::High
            } else {
                Confidence::Medium
            })
            .with_metadata(serde_json::json!({
                "sequence_confirmed": true,
                "confirmation_depth": confirmation_depth,
                "path_sensitive": true
            }))
            .with_remediation(
                "Enforce role- and object-level authorization for every request path. Validate ownership/tenant boundaries and deny access for unauthenticated or unrelated identities.",
            ),
    );
}

fn sequence_response(
    results: &[SequenceStepResult],
    step_name: &str,
) -> Option<crate::http_client::HttpResponse> {
    results
        .iter()
        .find(|res| res.name == step_name)
        .and_then(|res| res.response.clone())
}

fn idor_range_walk_severity(other_success_count: usize) -> Severity {
    match other_success_count {
        0 | 1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    }
}

fn is_sensitive_resource_path(url: &str) -> bool {
    const SENSITIVE_SEGMENTS: &[&str] = &[
        "admin", "account", "billing", "invoice", "order", "orders", "profile", "settings",
        "tenant", "user", "users", "internal", "private", "me",
    ];

    let parsed = match Url::parse(url) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let Some(segments) = parsed.path_segments() else {
        return false;
    };

    segments
        .map(|segment| segment.to_ascii_lowercase())
        .any(|segment| {
            SENSITIVE_SEGMENTS
                .iter()
                .any(|needle| segment == *needle || segment.starts_with(&format!("{needle}-")))
        })
}

// ── Numeric segment helpers ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct NumericSegment {
    /// The index in the path segments array.
    segment_index: usize,
    /// The numeric value.
    value: u64,
}

fn find_numeric_segment(url: &str) -> Option<NumericSegment> {
    let parsed = Url::parse(url).ok()?;
    let segments: Vec<String> = parsed.path_segments()?.map(|s| s.to_string()).collect();

    // Find the last numeric segment (most likely to be a resource ID)
    for (i, seg) in segments.iter().enumerate().rev() {
        if let Ok(num) = seg.parse::<u64>() {
            // Sanity-check: IDs are typically < 10 billion
            // Very large numbers are probably timestamps, not IDs
            if num < 10_000_000_000 {
                return Some(NumericSegment {
                    segment_index: i,
                    value: num,
                });
            }
        }
    }
    None
}

fn replace_numeric_segment(url: &str, seg: &NumericSegment, new_id: u64) -> String {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return url.to_string(),
    };
    let mut segments: Vec<String> = match parsed.path_segments() {
        Some(s) => s.map(|s| s.to_string()).collect(),
        None => return url.to_string(),
    };

    segments[seg.segment_index] = new_id.to_string();
    let new_path = format!("/{}", segments.join("/"));
    let mut new_url = parsed.clone();
    new_url.set_path(&new_path);
    new_url.to_string()
}
