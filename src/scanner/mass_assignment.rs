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
    let mut out = Vec::new();
    for key in ["is_admin", "role", "permissions"] {
        let needle = format!("\"{key}\"");
        if body.contains(&needle) {
            out.push(key);
        }
    }
    out
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
                let key = k.to_ascii_lowercase();
                match key.as_str() {
                    "is_admin" if v.as_bool() == Some(true) => {
                        out.insert("is_admin");
                    }
                    "role" => {
                        if let Some(role) = v.as_str() {
                            let r = role.to_ascii_lowercase();
                            if matches!(r.as_str(), "admin" | "superadmin" | "owner") {
                                out.insert("role");
                            }
                        }
                    }
                    "permissions" | "roles" => {
                        if let Some(arr) = v.as_array() {
                            let has_priv = arr.iter().any(|item| {
                                item.as_str().map(|s| {
                                    let p = s.to_ascii_lowercase();
                                    p == "*" || p == "admin" || p == "owner"
                                }) == Some(true)
                            });
                            if has_priv {
                                out.insert(if key == "permissions" {
                                    "permissions"
                                } else {
                                    "role"
                                });
                            }
                        }
                    }
                    _ => {}
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
