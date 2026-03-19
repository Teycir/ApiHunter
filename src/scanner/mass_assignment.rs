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

        let ct = resp
            .headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let json_like =
            ct.contains("json") || serde_json::from_str::<serde_json::Value>(&resp.body).is_ok();
        if !json_like {
            return (findings, errors);
        }

        let reflected = reflected_probe_fields(&resp.body);
        if !reflected.is_empty() {
            let mut confirmed_fields = Vec::new();
            if let Some(before_elevated) = baseline_elevated.as_ref() {
                match fetch_elevated_fields(client, url).await {
                    Ok(after_elevated) => {
                        let before: HashSet<&'static str> =
                            before_elevated.iter().copied().collect();
                        let after: HashSet<&'static str> = after_elevated.into_iter().collect();
                        let reflected_set: HashSet<&'static str> =
                            reflected.iter().copied().collect();

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
        }

        (findings, errors)
    }
}

fn is_likely_mutation_target(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    MUTATION_HINTS.iter().any(|k| lower.contains(k))
}

fn reflected_probe_fields(body: &str) -> Vec<&'static str> {
    elevated_fields_from_json(body)
}

async fn fetch_elevated_fields(
    client: &HttpClient,
    url: &str,
) -> Result<Vec<&'static str>, CapturedError> {
    let resp = client.get(url).await?;

    if resp.status >= 400 {
        return Ok(Vec::new());
    }

    let ct = resp
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let json_like =
        ct.contains("json") || serde_json::from_str::<serde_json::Value>(&resp.body).is_ok();
    if !json_like {
        return Ok(Vec::new());
    }

    Ok(elevated_fields_from_json(&resp.body))
}

fn elevated_fields_from_json(body: &str) -> Vec<&'static str> {
    let parsed = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = HashSet::new();
    collect_elevated_fields(&parsed, &mut out);
    out.into_iter().collect()
}

fn collect_elevated_fields(value: &serde_json::Value, out: &mut HashSet<&'static str>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let Some(field) = canonical_sensitive_field(k) {
                    if is_elevated_sensitive_value(field, v) {
                        out.insert(field);
                    }
                }
                collect_elevated_fields(v, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_elevated_fields(item, out);
            }
        }
        _ => {}
    }
}

fn canonical_sensitive_field(key: &str) -> Option<&'static str> {
    let normalized: String = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect();

    match normalized.as_str() {
        "isadmin" | "isadministrator" => Some("is_admin"),
        "role" | "roles" | "userrole" | "accountrole" => Some("role"),
        "permission" | "permissions" | "scope" | "scopes" => Some("permissions"),
        _ => None,
    }
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
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "admin"
    )
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
    matches!(
        token.trim().to_ascii_lowercase().as_str(),
        "admin" | "superadmin" | "owner" | "root"
    )
}

fn is_privileged_permission_token(token: &str) -> bool {
    matches!(
        token.trim().to_ascii_lowercase().as_str(),
        "*" | "admin" | "owner" | "root" | "all"
    )
}
