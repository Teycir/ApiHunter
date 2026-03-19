use async_trait::async_trait;
use serde_json::json;
use std::collections::HashSet;
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Severity},
};

use super::{
    common::finding_builder::FindingBuilder, common::http_utils::parse_json_response, Scanner,
};

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
    "users",
    "user",
    "account",
    "profile",
    "admin",
    "settings",
    "roles",
    "permissions",
];

#[async_trait]
impl Scanner for MassAssignmentScanner {
    fn name(&self) -> &'static str {
        "mass_assignment"
    }

    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        if should_skip_scan(config, url) {
            return (Vec::new(), Vec::new());
        }

        if config.dry_run {
            let payload = create_probe_payload(&[]);
            return (vec![create_dry_run_finding(url, &payload)], Vec::new());
        }

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut candidate_probe_fields = Vec::new();

        let baseline_elevated = match fetch_baseline_observation(client, url, "baseline_get").await
        {
            Ok((fields, candidates)) => {
                candidate_probe_fields = candidates;
                Some(fields)
            }
            Err(e) => {
                errors.push(e);
                None
            }
        };
        let payload = create_probe_payload(&candidate_probe_fields);

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
        let mut confirmation_failed = false;
        if let Some(before_elevated) = baseline_elevated.as_ref() {
            match fetch_elevated_fields(client, url, "confirm_get").await {
                Ok(after_elevated) => {
                    confirmed_fields =
                        compute_newly_elevated_fields(before_elevated, after_elevated, &reflected);
                }
                Err(e) => {
                    confirmation_failed = true;
                    errors.push(e);
                }
            }
        }

        if !confirmed_fields.is_empty() {
            confirmed_fields.sort_unstable();
            findings.push(create_mass_assignment_finding(
                url,
                resp.status,
                &reflected,
                Some(&confirmed_fields),
                false,
            ));
        } else {
            findings.push(create_mass_assignment_finding(
                url,
                resp.status,
                &reflected,
                None,
                confirmation_failed,
            ));
        }

        (findings, errors)
    }
}

fn should_skip_scan(config: &Config, url: &str) -> bool {
    !config.active_checks || !is_likely_mutation_target(url)
}

fn is_likely_mutation_target(url: &str) -> bool {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let path = parsed.path().trim_end_matches('/');
    let Some(last_segment) = path.rsplit('/').next() else {
        return false;
    };
    if last_segment.is_empty() {
        return false;
    }
    let last_segment_l = last_segment.to_ascii_lowercase();
    MUTATION_HINTS.iter().any(|hint| last_segment_l == *hint)
}

fn should_skip_response_status(status: u16) -> bool {
    status >= 400
}

fn reflected_probe_fields_from_value(value: &serde_json::Value) -> Vec<String> {
    elevated_fields_from_value(value)
}

async fn fetch_baseline_observation(
    client: &HttpClient,
    url: &str,
    phase: &'static str,
) -> Result<(Vec<String>, Vec<String>), CapturedError> {
    let resp = client
        .get(url)
        .await
        .map_err(|e| annotate_error(e, phase))?;

    if should_skip_response_status(resp.status) {
        return Ok((Vec::new(), Vec::new()));
    }

    let Some(parsed) = parse_json_response(&resp) else {
        return Ok((Vec::new(), Vec::new()));
    };

    Ok((
        elevated_fields_from_value(&parsed),
        sensitive_candidate_fields_from_value(&parsed),
    ))
}

async fn fetch_elevated_fields(
    client: &HttpClient,
    url: &str,
    phase: &'static str,
) -> Result<Vec<String>, CapturedError> {
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
    before: &[String],
    after: Vec<String>,
    reflected: &[String],
) -> Vec<String> {
    let before_set: HashSet<String> = before.iter().cloned().collect();
    let after_set: HashSet<String> = after.into_iter().collect();
    let reflected_set: HashSet<String> = reflected.iter().cloned().collect();

    let mut confirmed = Vec::new();
    for field in after_set.difference(&before_set) {
        if reflected_set.contains(field) {
            confirmed.push(field.clone());
        }
    }
    confirmed.sort_unstable();
    confirmed
}

fn elevated_fields_from_value(parsed: &serde_json::Value) -> Vec<String> {
    let mut out = HashSet::new();
    collect_elevated_fields(parsed, &mut out);
    let mut fields: Vec<String> = out.into_iter().collect();
    fields.sort_unstable();
    fields
}

fn collect_elevated_fields(value: &serde_json::Value, out: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let Some(field) = canonical_sensitive_field(k) {
                    if is_elevated_sensitive_value(&field, v) {
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

fn canonical_sensitive_field(key: &str) -> Option<String> {
    if key_matches_normalized(key, "isadmin") || key_matches_normalized(key, "isadministrator") {
        return Some("is_admin".to_string());
    }

    if key_matches_normalized(key, "role")
        || key_matches_normalized(key, "roles")
        || key_matches_normalized(key, "userrole")
        || key_matches_normalized(key, "accountrole")
    {
        return Some("role".to_string());
    }

    if key_matches_normalized(key, "permission")
        || key_matches_normalized(key, "permissions")
        || key_matches_normalized(key, "scope")
        || key_matches_normalized(key, "scopes")
    {
        return Some("permissions".to_string());
    }

    let normalized = normalize_key(key);
    if is_sensitive_key_hint(&normalized) {
        return Some(normalized);
    }

    None
}

fn is_elevated_sensitive_value(field: &str, value: &serde_json::Value) -> bool {
    match sensitive_kind(field) {
        SensitiveKind::BooleanFlag => match value {
            serde_json::Value::Bool(true) => true,
            serde_json::Value::Number(n) => n.as_i64() == Some(1),
            serde_json::Value::String(s) => is_truthy_string(s),
            _ => false,
        },
        SensitiveKind::RoleLike => value_is_privileged_role(value),
        SensitiveKind::PermissionLike => value_has_privileged_permission(value),
    }
}

fn sensitive_candidate_fields_from_value(parsed: &serde_json::Value) -> Vec<String> {
    let mut out = HashSet::new();

    // Always keep canonical probe fields in the payload.
    out.insert("is_admin".to_string());
    out.insert("role".to_string());
    out.insert("permissions".to_string());
    collect_sensitive_candidate_fields(parsed, &mut out);

    let mut fields: Vec<String> = out.into_iter().collect();
    fields.sort_unstable();
    fields
}

fn collect_sensitive_candidate_fields(value: &serde_json::Value, out: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if is_sensitive_key_hint(&normalize_key(k)) {
                    out.insert(k.clone());
                }
                collect_sensitive_candidate_fields(v, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_sensitive_candidate_fields(item, out);
            }
        }
        _ => {}
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
        || token.eq_ignore_ascii_case("superuser")
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

fn normalize_key(key: &str) -> String {
    key.bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| (b as char).to_ascii_lowercase())
        .collect()
}

fn is_sensitive_key_hint(normalized: &str) -> bool {
    if normalized.is_empty() {
        return false;
    }

    const HINTS: &[&str] = &[
        "admin",
        "administrator",
        "superuser",
        "superadmin",
        "owner",
        "root",
        "privilege",
        "permission",
        "scope",
        "role",
        "accesstype",
        "accesslevel",
        "authority",
        "accounttype",
        "usertype",
        "entitlement",
        "isadmin",
        "isowner",
        "isroot",
        "elevated",
    ];

    HINTS.iter().any(|hint| normalized.contains(hint))
}

#[derive(Clone, Copy)]
enum SensitiveKind {
    BooleanFlag,
    RoleLike,
    PermissionLike,
}

fn sensitive_kind(field: &str) -> SensitiveKind {
    let normalized = normalize_key(field);
    if normalized == "permissions"
        || normalized.contains("permission")
        || normalized.contains("scope")
        || normalized.contains("privilege")
        || normalized.contains("entitlement")
    {
        return SensitiveKind::PermissionLike;
    }

    if normalized == "role"
        || normalized.contains("role")
        || normalized.contains("type")
        || normalized.contains("level")
        || normalized.contains("group")
        || normalized.contains("tier")
        || normalized.contains("class")
    {
        return SensitiveKind::RoleLike;
    }

    SensitiveKind::BooleanFlag
}

fn probe_value_for_field(field: &str) -> serde_json::Value {
    match sensitive_kind(field) {
        SensitiveKind::BooleanFlag => json!(true),
        SensitiveKind::RoleLike => json!("admin"),
        SensitiveKind::PermissionLike => json!(["*"]),
    }
}

fn create_mass_assignment_finding(
    url: &str,
    status: u16,
    reflected: &[String],
    confirmed: Option<&[String]>,
    confirmation_failed: bool,
) -> Finding {
    if let Some(confirmed_fields) = confirmed {
        FindingBuilder::new(url, "mass_assignment")
        .check("mass_assignment/persisted-state-change")
        .title("Potential persisted privilege/state change")
        .severity(Severity::High)
        .detail("Sensitive fields appear newly elevated after crafted field injection.")
        .build()
        .with_evidence(format!(
            "POST {url}\nStatus: {status}\nReflected fields: {}\nNewly elevated after confirm GET: {}",
            reflected.join(", "),
            confirmed_fields.join(", ")
        ))
        .with_remediation(
            "Block sensitive fields from client-controlled input and enforce server-side authorization invariants.",
        )
    } else {
        let mut evidence = format!(
            "POST {url}\nStatus: {status}\nReflected fields: {}",
            reflected.join(", ")
        );
        if confirmation_failed {
            evidence
                .push_str("\nNote: Confirmation GET failed; persistence could not be verified.");
        }

        FindingBuilder::new(url, "mass_assignment")
        .check("mass_assignment/reflected-fields")
        .title("Potential mass-assignment via reflected fields")
        .severity(Severity::Medium)
        .detail("Response reflected crafted sensitive fields from request payload.")
        .build()
        .with_evidence(evidence)
        .with_remediation(
            "Use explicit allowlists for writeable fields and reject unexpected attributes server-side.",
        )
    }
}

fn create_probe_payload(candidate_keys: &[String]) -> serde_json::Value {
    let mut payload = serde_json::Map::new();

    for key in candidate_keys {
        if key.trim().is_empty() {
            continue;
        }
        payload
            .entry(key.clone())
            .or_insert_with(|| probe_value_for_field(key));
    }

    for key in ["is_admin", "role", "permissions"] {
        payload
            .entry(key.to_string())
            .or_insert_with(|| probe_value_for_field(key));
    }

    serde_json::Value::Object(payload)
}

fn create_dry_run_finding(url: &str, payload: &serde_json::Value) -> Finding {
    FindingBuilder::new(url, "mass_assignment")
        .check("mass_assignment/dry-run")
        .title("Mass assignment dry run")
        .severity(Severity::Info)
        .detail("Dry-run mode enabled; no mutation probe was sent.")
        .build()
        .with_evidence(format!("Would POST payload: {payload}"))
}

fn annotate_error(mut err: CapturedError, phase: &'static str) -> CapturedError {
    err.message = format!("{phase}: {}", err.message);
    err
}
