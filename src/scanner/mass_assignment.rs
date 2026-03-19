use async_trait::async_trait;
use serde_json::json;
use std::collections::HashSet;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Severity},
};

use super::{http_utils::parse_json_response, Scanner};

/// Detects potential mass-assignment vulnerabilities by injecting privileged fields.
///
/// # How It Works
/// 1. Baseline `GET` captures currently elevated sensitive fields.
/// 2. Active probe sends `POST` with privileged fields.
/// 3. Confirmation `GET` checks whether reflected fields persisted as newly elevated state.
///
/// # Findings
/// - `mass_assignment/reflected-fields` (`MEDIUM`): privileged fields reflected in response.
/// - `mass_assignment/persisted-state-change` (`HIGH`): reflected fields also persisted in state.
/// - `mass_assignment/dry-run` (`INFO`): scanner configured to report planned probe only.
pub struct MassAssignmentScanner;

impl MassAssignmentScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

static MUTATION_HINTS: &[&str] = &[
    "/users",
    "/user",
    "/account",
    "/profile",
    "/admin",
    "/settings",
    "/roles",
    "/permissions",
];

#[async_trait]
impl Scanner for MassAssignmentScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        if should_skip_scan(config, url) {
            return (Vec::new(), Vec::new());
        }

        let payload = create_probe_payload();
        if config.dry_run {
            return (vec![create_dry_run_finding(url, &payload)], Vec::new());
        }

        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let baseline_elevated = match fetch_elevated_fields(client, url, "baseline_get").await {
            Ok(fields) => Some(fields),
            Err(e) => {
                errors.push(e);
                None
            }
        };

        let resp = match client
            .post_json(url, &payload)
            .await
            .map_err(|e| annotate_error(e, "probe_post"))
        {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                return (findings, errors);
            }
        };

        if should_skip_response_status(resp.status) {
            return (findings, errors);
        }

        let parsed_post = match parse_json_response(&resp) {
            Some(v) => v,
            None => return (findings, errors),
        };

        let reflected = reflected_probe_fields_from_value(&parsed_post);
        if reflected.is_empty() {
            return (findings, errors);
        }

        let mut confirmed_fields = Vec::new();
        if let Some(before_elevated) = baseline_elevated.as_ref() {
            match fetch_elevated_fields(client, url, "confirm_get").await {
                Ok(after_elevated) => {
                    confirmed_fields =
                        compute_newly_elevated_fields(before_elevated, after_elevated, &reflected);
                }
                Err(e) => errors.push(e),
            }
        }

        if !confirmed_fields.is_empty() {
            confirmed_fields.sort_unstable();
            findings.push(create_mass_assignment_finding(
                url,
                resp.status,
                &reflected,
                Some(&confirmed_fields),
            ));
        } else {
            findings.push(create_mass_assignment_finding(
                url,
                resp.status,
                &reflected,
                None,
            ));
        }

        (findings, errors)
    }
}

fn should_skip_scan(config: &Config, url: &str) -> bool {
    !config.active_checks || !is_likely_mutation_target(url)
}

fn is_likely_mutation_target(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    MUTATION_HINTS.iter().any(|k| lower.contains(k))
}

fn should_skip_response_status(status: u16) -> bool {
    status >= 400
}

fn reflected_probe_fields_from_value(value: &serde_json::Value) -> Vec<&'static str> {
    elevated_fields_from_value(value)
}

async fn fetch_elevated_fields(
    client: &HttpClient,
    url: &str,
    phase: &'static str,
) -> Result<Vec<&'static str>, CapturedError> {
    let resp = client
        .get(url)
        .await
        .map_err(|e| annotate_error(e, phase))?;

    if should_skip_response_status(resp.status) {
        return Ok(Vec::new());
    }

    let Some(parsed) = parse_json_response(&resp) else {
        return Ok(Vec::new());
    };

    Ok(elevated_fields_from_value(&parsed))
}

fn compute_newly_elevated_fields(
    before: &[&'static str],
    after: Vec<&'static str>,
    reflected: &[&'static str],
) -> Vec<&'static str> {
    let before_set: HashSet<&'static str> = before.iter().copied().collect();
    let after_set: HashSet<&'static str> = after.into_iter().collect();
    let reflected_set: HashSet<&'static str> = reflected.iter().copied().collect();

    let mut confirmed = Vec::new();
    for field in after_set.difference(&before_set) {
        if reflected_set.contains(field) {
            confirmed.push(*field);
        }
    }
    confirmed.sort_unstable();
    confirmed
}

fn elevated_fields_from_value(parsed: &serde_json::Value) -> Vec<&'static str> {
    let mut out = HashSet::with_capacity(3);
    collect_elevated_fields(parsed, &mut out);
    let mut fields: Vec<&'static str> = out.into_iter().collect();
    fields.sort_unstable();
    fields
}

fn collect_elevated_fields(value: &serde_json::Value, out: &mut HashSet<&'static str>) {
    if out.len() == 3 {
        return;
    }

    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let Some(field) = canonical_sensitive_field(k) {
                    if is_elevated_sensitive_value(field, v) {
                        out.insert(field);
                        if out.len() == 3 {
                            return;
                        }
                    }
                }
                collect_elevated_fields(v, out);
                if out.len() == 3 {
                    return;
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_elevated_fields(item, out);
                if out.len() == 3 {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn canonical_sensitive_field(key: &str) -> Option<&'static str> {
    if key_matches_normalized(key, "isadmin") || key_matches_normalized(key, "isadministrator") {
        return Some("is_admin");
    }

    if key_matches_normalized(key, "role")
        || key_matches_normalized(key, "roles")
        || key_matches_normalized(key, "userrole")
        || key_matches_normalized(key, "accountrole")
    {
        return Some("role");
    }

    if key_matches_normalized(key, "permission")
        || key_matches_normalized(key, "permissions")
        || key_matches_normalized(key, "scope")
        || key_matches_normalized(key, "scopes")
    {
        return Some("permissions");
    }

    None
}

fn is_elevated_sensitive_value(field: &str, value: &serde_json::Value) -> bool {
    match field {
        "is_admin" => match value {
            serde_json::Value::Bool(true) => true,
            serde_json::Value::Number(n) => n.as_i64() == Some(1),
            serde_json::Value::String(s) => is_truthy_string(s),
            _ => false,
        },
        "role" => value_is_privileged_role(value),
        "permissions" => value_has_privileged_permission(value),
        _ => false,
    }
}

fn is_truthy_string(s: &str) -> bool {
    let token = s.trim();
    token == "1"
        || token.eq_ignore_ascii_case("true")
        || token.eq_ignore_ascii_case("yes")
        || token.eq_ignore_ascii_case("on")
        || token.eq_ignore_ascii_case("admin")
}

fn value_is_privileged_role(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => is_privileged_role_token(s),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| item.as_str())
            .any(is_privileged_role_token),
        _ => false,
    }
}

fn value_has_privileged_permission(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => is_privileged_permission_token(s),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| item.as_str())
            .any(is_privileged_permission_token),
        _ => false,
    }
}

fn is_privileged_role_token(token: &str) -> bool {
    let token = token.trim();
    token.eq_ignore_ascii_case("admin")
        || token.eq_ignore_ascii_case("superadmin")
        || token.eq_ignore_ascii_case("owner")
        || token.eq_ignore_ascii_case("root")
}

fn is_privileged_permission_token(token: &str) -> bool {
    let token = token.trim();
    token == "*"
        || token.eq_ignore_ascii_case("admin")
        || token.eq_ignore_ascii_case("owner")
        || token.eq_ignore_ascii_case("root")
        || token.eq_ignore_ascii_case("all")
}

fn key_matches_normalized(key: &str, normalized: &str) -> bool {
    let mut key_iter = key
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b.to_ascii_lowercase());

    for expected in normalized.bytes() {
        match key_iter.next() {
            Some(actual) if actual == expected => {}
            _ => return false,
        }
    }

    key_iter.next().is_none()
}

fn create_mass_assignment_finding(
    url: &str,
    status: u16,
    reflected: &[&'static str],
    confirmed: Option<&[&'static str]>,
) -> Finding {
    if let Some(confirmed_fields) = confirmed {
        Finding::new(
            url,
            "mass_assignment/persisted-state-change",
            "Potential persisted privilege/state change",
            Severity::High,
            "Sensitive fields appear newly elevated after crafted field injection.",
            "mass_assignment",
        )
        .with_evidence(format!(
            "POST {url}\nStatus: {status}\nReflected fields: {}\nNewly elevated after confirm GET: {}",
            reflected.join(", "),
            confirmed_fields.join(", ")
        ))
        .with_remediation(
            "Block sensitive fields from client-controlled input and enforce server-side authorization invariants.",
        )
    } else {
        Finding::new(
            url,
            "mass_assignment/reflected-fields",
            "Potential mass-assignment via reflected fields",
            Severity::Medium,
            "Response reflected crafted sensitive fields from request payload.",
            "mass_assignment",
        )
        .with_evidence(format!(
            "POST {url}\nStatus: {status}\nReflected fields: {}",
            reflected.join(", ")
        ))
        .with_remediation(
            "Use explicit allowlists for writeable fields and reject unexpected attributes server-side.",
        )
    }
}

fn create_probe_payload() -> serde_json::Value {
    json!({
        "is_admin": true,
        "role": "admin",
        "permissions": ["*"]
    })
}

fn create_dry_run_finding(url: &str, payload: &serde_json::Value) -> Finding {
    Finding::new(
        url,
        "mass_assignment/dry-run",
        "Mass assignment dry run",
        Severity::Info,
        "Dry-run mode enabled; no mutation probe was sent.",
        "mass_assignment",
    )
    .with_evidence(format!("Would POST payload: {payload}"))
}

fn annotate_error(mut err: CapturedError, phase: &'static str) -> CapturedError {
    err.message = format!("{phase}: {}", err.message);
    err
}
