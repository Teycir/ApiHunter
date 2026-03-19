use async_trait::async_trait;
use serde_json::json;
use std::collections::HashSet;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Severity},
};

use super::Scanner;

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
        if !config.active_checks || !is_likely_mutation_target(url) {
            return (Vec::new(), Vec::new());
        }

        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let baseline_elevated = match fetch_elevated_fields(client, url).await {
            Ok(fields) => Some(fields),
            Err(e) => {
                errors.push(e);
                None
            }
        };

        let payload = json!({
            "is_admin": true,
            "role": "admin",
            "permissions": ["*"]
        });

        let resp = match client.post_json(url, &payload).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                return (findings, errors);
            }
        };

        if resp.status >= 400 {
            return (findings, errors);
        }

        let parsed_post = match parse_json_body(
            &resp.body,
            resp.headers.get("content-type").map(|s| s.as_str()),
        ) {
            Some(v) => v,
            None => return (findings, errors),
        };

        let reflected = reflected_probe_fields_from_value(&parsed_post);
        if reflected.is_empty() {
            return (findings, errors);
        }

        let mut confirmed_fields = Vec::new();
        if let Some(before_elevated) = baseline_elevated.as_ref() {
            match fetch_elevated_fields(client, url).await {
                Ok(after_elevated) => {
                    let before: HashSet<&'static str> = before_elevated.iter().copied().collect();
                    let after: HashSet<&'static str> = after_elevated.into_iter().collect();
                    let reflected_set: HashSet<&'static str> = reflected.iter().copied().collect();

                    for field in after.difference(&before) {
                        if reflected_set.contains(field) {
                            confirmed_fields.push(*field);
                        }
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        if !confirmed_fields.is_empty() {
            confirmed_fields.sort_unstable();
            findings.push(
                Finding::new(
                    url,
                    "mass_assignment/persisted-state-change",
                    "Potential persisted privilege/state change",
                    Severity::High,
                    "Sensitive fields appear newly elevated after crafted field injection.",
                    "mass_assignment",
                )
                .with_evidence(format!(
                    "POST {url}\nStatus: {}\nReflected fields: {}\nNewly elevated after confirm GET: {}",
                    resp.status,
                    reflected.join(", "),
                    confirmed_fields.join(", ")
                ))
                .with_remediation(
                    "Block sensitive fields from client-controlled input and enforce server-side authorization invariants.",
                ),
            );
        } else {
            findings.push(
                Finding::new(
                    url,
                    "mass_assignment/reflected-fields",
                    "Potential mass-assignment via reflected fields",
                    Severity::Medium,
                    "Response reflected crafted sensitive fields from request payload.",
                    "mass_assignment",
                )
                .with_evidence(format!(
                    "POST {url}\nStatus: {}\nReflected fields: {}",
                    resp.status,
                    reflected.join(", ")
                ))
                .with_remediation(
                    "Use explicit allowlists for writeable fields and reject unexpected attributes server-side.",
                ),
            );
        }

        (findings, errors)
    }
}

fn is_likely_mutation_target(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    MUTATION_HINTS.iter().any(|k| lower.contains(k))
}

fn reflected_probe_fields_from_value(value: &serde_json::Value) -> Vec<&'static str> {
    elevated_fields_from_value(value)
}

async fn fetch_elevated_fields(
    client: &HttpClient,
    url: &str,
) -> Result<Vec<&'static str>, CapturedError> {
    let resp = client.get(url).await?;

    if resp.status >= 400 {
        return Ok(Vec::new());
    }

    let Some(parsed) = parse_json_body(
        &resp.body,
        resp.headers.get("content-type").map(|s| s.as_str()),
    ) else {
        return Ok(Vec::new());
    };

    Ok(elevated_fields_from_value(&parsed))
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

fn parse_json_body(body: &str, content_type: Option<&str>) -> Option<serde_json::Value> {
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
    let is_json_content_type = content_type.map(content_type_is_json).unwrap_or(false);

    if is_json_content_type || parsed.is_some() {
        parsed
    } else {
        None
    }
}

fn content_type_is_json(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    media_type
        .as_bytes()
        .windows(4)
        .any(|window| window.eq_ignore_ascii_case(b"json"))
}
