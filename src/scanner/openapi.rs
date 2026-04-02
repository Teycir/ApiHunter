// src/scanner/openapi.rs
//
// OpenAPI / Swagger spec security analysis.

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method,
};
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
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

use super::Scanner;

pub struct OpenApiScanner;

impl OpenApiScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

/// Well-known OpenAPI / Swagger spec locations to probe.
static SPEC_PATHS: &[&str] = &[
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api-docs.yaml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/api-docs",
    "/v3/api-docs.yaml",
];

const MAX_SCHEMA_FUZZ_OPERATIONS: usize = 8;
const MAX_RACE_PROBES: usize = 4;
const MAX_OAST_PROBES: usize = 4;
const RACE_BURST_REQUESTS: usize = 4;
const OAST_BASE_ENV: &str = "APIHUNTER_OAST_BASE";
const STRING_INJECTION_PAYLOAD: &str = "apihunter' OR '1'='1";

const RESPONSE_ERROR_MARKERS: &[&str] = &[
    "sql syntax",
    "syntax error",
    "traceback",
    "exception",
    "stack trace",
    "internal server error",
    "panic:",
    "nullpointerexception",
];

const OAST_FIELD_KEYWORDS: &[&str] = &[
    "url", "uri", "callback", "webhook", "redirect", "endpoint", "image", "avatar", "target",
    "hook",
];

const RACE_SENSITIVE_KEYWORDS: &[&str] = &[
    "transfer", "payment", "payments", "withdraw", "checkout", "order", "orders", "purchase",
    "redeem", "wallet", "balance",
];

#[derive(Debug, Clone)]
struct SchemaOperation {
    method: Method,
    method_name: String,
    path: String,
    body_schema: Value,
    operation_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ProbeVariant {
    name: &'static str,
    payload: Value,
}

#[async_trait]
impl Scanner for OpenApiScanner {
    fn name(&self) -> &'static str {
        "openapi"
    }

    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut probed_ops: HashSet<String> = HashSet::new();

        let base = url.trim_end_matches('/');

        for spec_path in SPEC_PATHS {
            let spec_url = format!("{base}{spec_path}");
            let body = if let Some(cached) = client.get_cached_spec(&spec_url) {
                cached
            } else {
                let resp = match client.get(&spec_url).await {
                    Ok(r) if r.status < 400 => r,
                    Ok(_) => continue,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };
                client.cache_spec(&spec_url, &resp.body);
                resp.body
            };

            debug!("[openapi] found spec at {spec_url}");

            match parse_spec(&body) {
                Ok(spec) => {
                    analyze_spec(&spec_url, &spec, &mut findings);
                    if config.active_checks {
                        run_active_spec_probes(
                            url,
                            &spec,
                            client,
                            config,
                            &mut findings,
                            &mut errors,
                            &mut probed_ops,
                        )
                        .await;
                    }
                }
                Err(e) => errors.push(CapturedError::parse("openapi/parse", e)),
            }
        }

        (findings, errors)
    }
}

fn parse_spec(body: &str) -> Result<Value, String> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        serde_json::from_str::<Value>(trimmed).map_err(|e| e.to_string())
    } else {
        serde_yml::from_str::<Value>(trimmed).map_err(|e| e.to_string())
    }
}

fn analyze_spec(spec_url: &str, spec: &Value, findings: &mut Vec<Finding>) {
    let mut unsecured_ops = Vec::new();
    let mut deprecated_ops = Vec::new();
    let mut upload_ops = Vec::new();

    let security_schemes = spec
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .or_else(|| spec.get("securityDefinitions"));

    let has_security_schemes = security_schemes
        .and_then(|v| v.as_object())
        .map(|o| !o.is_empty())
        .unwrap_or(false);

    let global_security = spec
        .get("security")
        .and_then(|v| v.as_array())
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    if !has_security_schemes {
        findings.push(
            Finding::new(
                spec_url,
                "openapi/no-security-schemes",
                "OpenAPI spec missing security schemes",
                Severity::Medium,
                "No securitySchemes (OAS3) or securityDefinitions (Swagger v2) were defined.",
                "openapi",
            )
            .with_remediation(
                "Define authentication schemes in the spec (e.g., OAuth2, API key, JWT).",
            ),
        );
    }

    let paths = spec.get("paths").and_then(|v| v.as_object());
    if let Some(paths) = paths {
        for (path, item) in paths {
            let item_obj = match item.as_object() {
                Some(v) => v,
                None => continue,
            };

            for (method, op) in item_obj {
                if !is_http_method(method) {
                    continue;
                }

                let op_obj = match op.as_object() {
                    Some(v) => v,
                    None => continue,
                };

                let op_security = op_obj.get("security").and_then(|v| v.as_array());
                let secured = op_security
                    .map(|v| !v.is_empty())
                    .unwrap_or(global_security);

                if !secured {
                    unsecured_ops.push(format!("{} {}", method.to_uppercase(), path));
                }

                if op_obj.get("deprecated").and_then(|v| v.as_bool()) == Some(true) {
                    deprecated_ops.push(format!("{} {}", method.to_uppercase(), path));
                }

                if looks_like_file_upload(op_obj) {
                    upload_ops.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        }
    }

    if !unsecured_ops.is_empty() {
        let sample = unsecured_ops
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(
            Finding::new(
                spec_url,
                "openapi/unauthenticated-operations",
                "OpenAPI operations without security requirements",
                Severity::Medium,
                format!(
                    "{} operation(s) do not declare security requirements.",
                    unsecured_ops.len()
                ),
                "openapi",
            )
            .with_evidence(format!("Sample: {sample}"))
            .with_remediation("Apply security requirements globally or per-operation in the spec."),
        );
    }

    if !upload_ops.is_empty() {
        let sample = upload_ops
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(
            Finding::new(
                spec_url,
                "openapi/file-upload",
                "OpenAPI file upload endpoints",
                Severity::Medium,
                format!("{} operation(s) accept file uploads.", upload_ops.len()),
                "openapi",
            )
            .with_evidence(format!("Sample: {sample}"))
            .with_remediation(
                "Harden file upload endpoints with size limits, content-type validation, and auth.",
            ),
        );
    }

    if !deprecated_ops.is_empty() {
        let sample = deprecated_ops
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(
            Finding::new(
                spec_url,
                "openapi/deprecated-operations",
                "Deprecated OpenAPI operations still present",
                Severity::Info,
                format!(
                    "{} deprecated operation(s) listed in the spec.",
                    deprecated_ops.len()
                ),
                "openapi",
            )
            .with_evidence(format!("Sample: {sample}"))
            .with_remediation("Remove deprecated endpoints or add explicit sunset timelines."),
        );
    }
}

async fn run_active_spec_probes(
    seed_url: &str,
    spec: &Value,
    client: &HttpClient,
    config: &Config,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
    probed_ops: &mut HashSet<String>,
) {
    let operations = collect_schema_operations(spec);
    if operations.is_empty() {
        return;
    }

    let oast_base = std::env::var(OAST_BASE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let mut schema_probes = 0usize;
    let mut race_probes = 0usize;
    let mut oast_probes = 0usize;

    for operation in operations {
        let Some(op_url) = materialize_operation_url(seed_url, spec, &operation.path) else {
            continue;
        };

        let probe_key = format!("{} {}", operation.method_name, op_url);
        if !probed_ops.insert(probe_key) {
            continue;
        }

        let Some(base_payload) = synthesize_payload(&operation.body_schema, spec, 0) else {
            continue;
        };

        if schema_probes < MAX_SCHEMA_FUZZ_OPERATIONS {
            run_schema_fuzz_probe(
                &operation,
                &op_url,
                &base_payload,
                client,
                config,
                findings,
                errors,
            )
            .await;
            schema_probes += 1;
        }

        if race_probes < MAX_RACE_PROBES && should_race_probe(&operation) {
            run_race_probe(
                &operation,
                &op_url,
                &base_payload,
                client,
                config,
                findings,
                errors,
            )
            .await;
            race_probes += 1;
        }

        if oast_probes < MAX_OAST_PROBES {
            if let Some(base) = oast_base.as_deref() {
                match run_oast_probe(
                    &operation,
                    &op_url,
                    &base_payload,
                    base,
                    client,
                    config,
                    findings,
                )
                .await
                {
                    Ok(true) => oast_probes += 1,
                    Ok(false) => {}
                    Err(error) => errors.push(error),
                }
            }
        }
    }
}

async fn run_schema_fuzz_probe(
    operation: &SchemaOperation,
    url: &str,
    base_payload: &Value,
    client: &HttpClient,
    config: &Config,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let variants = build_schema_fuzz_variants(base_payload);
    if variants.is_empty() {
        return;
    }

    if config.dry_run {
        findings.push(
            Finding::new(
                url,
                "openapi/schema-fuzzing-dry-run",
                "Schema-aware fuzzing planned (dry run)",
                Severity::Info,
                "Active schema-aware fuzzing was skipped because --dry-run is enabled.",
                "openapi",
            )
            .with_evidence(format!(
                "Operation: {} {}\nVariants: {}",
                operation.method_name,
                operation.path,
                variants
                    .iter()
                    .map(|variant| variant.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .with_metadata(serde_json::json!({
                "operation": operation.operation_id,
                "path": operation.path,
                "method": operation.method_name,
                "variants": variants.iter().map(|variant| variant.name).collect::<Vec<_>>(),
                "sequence_confirmed": false
            }))
            .with_remediation(
                "Run again without --dry-run to execute schema-aware malformed payload probes.",
            ),
        );
        return;
    }

    let baseline = match client
        .request(
            operation.method.clone(),
            url,
            None,
            Some(base_payload.clone()),
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            errors.push(error);
            return;
        }
    };

    if baseline.status >= 500 {
        return;
    }

    for variant in variants {
        let response = match client
            .request(
                operation.method.clone(),
                url,
                None,
                Some(variant.payload.clone()),
            )
            .await
        {
            Ok(result) => result,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };

        if !is_suspicious_fuzz_response(&baseline, &response) {
            continue;
        }

        findings.push(
            Finding::new(
                url,
                "openapi/schema-fuzzing-suspected",
                "Schema-aware fuzzing triggered suspicious backend behavior",
                if response.status >= 500 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                "A schema-aware malformed payload changed server behavior and surfaced error signatures. This can indicate weak input validation or unsafe downstream handling.",
                "openapi",
            )
            .with_evidence(format!(
                "Operation: {} {}\nVariant: {}\nBaseline HTTP: {}\nVariant HTTP: {}\nVariant snippet: {}",
                operation.method_name,
                operation.path,
                variant.name,
                baseline.status,
                response.status,
                response.body.chars().take(220).collect::<String>()
            ))
            .with_confidence(if response.status >= 500 {
                Confidence::High
            } else {
                Confidence::Medium
            })
            .with_metadata(serde_json::json!({
                "operation": operation.operation_id,
                "path": operation.path,
                "method": operation.method_name,
                "variant": variant.name,
                "sequence_confirmed": true,
                "confirmation_depth": 2
            }))
            .with_remediation(
                "Harden request validation at schema and business layers, and ensure parser/ORM errors do not leak in API responses.",
            ),
        );

        break;
    }
}

async fn run_race_probe(
    operation: &SchemaOperation,
    url: &str,
    base_payload: &Value,
    client: &HttpClient,
    config: &Config,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    if config.dry_run {
        findings.push(
            Finding::new(
                url,
                "openapi/race-probe-dry-run",
                "Race-condition probe planned (dry run)",
                Severity::Info,
                "Race-condition probing was skipped because --dry-run is enabled.",
                "openapi",
            )
            .with_evidence(format!(
                "Operation: {} {}\nBurst size: {RACE_BURST_REQUESTS}",
                operation.method_name, operation.path
            ))
            .with_metadata(serde_json::json!({
                "operation": operation.operation_id,
                "path": operation.path,
                "method": operation.method_name,
                "burst": RACE_BURST_REQUESTS,
                "sequence_confirmed": false
            }))
            .with_remediation(
                "Run without --dry-run to execute duplicate concurrent mutation probes.",
            ),
        );
        return;
    }

    let baseline = match client
        .request(
            operation.method.clone(),
            url,
            None,
            Some(base_payload.clone()),
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            errors.push(error);
            return;
        }
    };

    if baseline.status >= 400 {
        return;
    }

    let token = correlation_token("race", &operation.path);
    let headers = race_headers(&token);

    let results = stream::iter(0..RACE_BURST_REQUESTS)
        .map(|_| {
            let payload = base_payload.clone();
            let headers = headers.clone();
            let method = operation.method.clone();
            let url = url.to_string();
            let client = client.clone();
            async move {
                client
                    .request_burst(method, &url, Some(headers), Some(payload))
                    .await
            }
        })
        .buffer_unordered(RACE_BURST_REQUESTS)
        .collect::<Vec<Result<HttpResponse, CapturedError>>>()
        .await;

    let mut statuses = Vec::new();
    for result in results {
        match result {
            Ok(response) => statuses.push(response.status),
            Err(error) => errors.push(error),
        }
    }

    if statuses.len() < 2 {
        return;
    }

    let success_count = statuses
        .iter()
        .filter(|status| (200u16..300u16).contains(status))
        .count();
    let conflict_count = statuses
        .iter()
        .filter(|status| matches!(**status, 409 | 425 | 429))
        .count();

    if success_count < 2 || conflict_count > 0 {
        return;
    }

    findings.push(
        Finding::new(
            url,
            "openapi/race-probe-possible-idempotency-gap",
            "Concurrent duplicate mutation requests succeeded",
            if success_count >= 3 {
                Severity::High
            } else {
                Severity::Medium
            },
            "Concurrent duplicate requests for a sensitive mutation endpoint succeeded without conflict responses. This can indicate missing idempotency or race-condition protections.",
            "openapi",
        )
        .with_evidence(format!(
            "Operation: {} {}\nToken: {}\nBurst statuses: {}",
            operation.method_name,
            operation.path,
            token,
            statuses
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .with_confidence(if success_count >= 3 {
            Confidence::High
        } else {
            Confidence::Medium
        })
        .with_metadata(serde_json::json!({
            "operation": operation.operation_id,
            "path": operation.path,
            "method": operation.method_name,
            "burst": RACE_BURST_REQUESTS,
            "token": token,
            "sequence_confirmed": true,
            "confirmation_depth": 2,
            "statuses": statuses,
        }))
        .with_remediation(
            "Implement idempotency keys and transactional guards for state-changing operations to prevent double execution under concurrent requests.",
        ),
    );
}

async fn run_oast_probe(
    operation: &SchemaOperation,
    url: &str,
    base_payload: &Value,
    oast_base: &str,
    client: &HttpClient,
    config: &Config,
    findings: &mut Vec<Finding>,
) -> Result<bool, CapturedError> {
    let token = correlation_token("oast", &operation.path);
    let callback_url = format!("{}/{}", oast_base.trim_end_matches('/'), token);

    let Some((field_path, payload)) = inject_oast_callback(base_payload, &callback_url) else {
        return Ok(false);
    };

    if config.dry_run {
        findings.push(
            Finding::new(
                url,
                "openapi/oast-probe-dry-run",
                "OAST callback probe planned (dry run)",
                Severity::Info,
                "OAST callback injection was skipped because --dry-run is enabled.",
                "openapi",
            )
            .with_evidence(format!(
                "Operation: {} {}\nField: {}\nCallback: {}",
                operation.method_name, operation.path, field_path, callback_url
            ))
            .with_metadata(serde_json::json!({
                "operation": operation.operation_id,
                "path": operation.path,
                "method": operation.method_name,
                "token": token,
                "callback_url": callback_url,
                "field": field_path,
                "sequence_confirmed": false
            }))
            .with_remediation(
                "Run without --dry-run and monitor your OAST server for callback hits.",
            ),
        );
        return Ok(true);
    }

    let response = client
        .request(operation.method.clone(), url, None, Some(payload))
        .await?;

    let reflected = response.body.contains(&token)
        || response
            .body
            .to_ascii_lowercase()
            .contains(&oast_base.to_ascii_lowercase());

    findings.push(
        Finding::new(
            url,
            if reflected {
                "openapi/oast-probe-reflected"
            } else {
                "openapi/oast-probe-dispatched"
            },
            if reflected {
                "OAST callback token reflected in response"
            } else {
                "OAST callback probe dispatched"
            },
            if reflected {
                Severity::Medium
            } else {
                Severity::Info
            },
            if reflected {
                "The OAST callback token appeared in the immediate API response. Validate whether callback URLs are being processed unsafely."
            } else {
                "A callback URL payload was dispatched for blind SSRF/callback detection. Verify hits in your OAST listener."
            },
            "openapi",
        )
        .with_evidence(format!(
            "Operation: {} {}\nField: {}\nCallback: {}\nHTTP: {}",
            operation.method_name, operation.path, field_path, callback_url, response.status
        ))
        .with_confidence(if reflected {
            Confidence::Medium
        } else {
            Confidence::Low
        })
        .with_metadata(serde_json::json!({
            "operation": operation.operation_id,
            "path": operation.path,
            "method": operation.method_name,
            "token": token,
            "callback_url": callback_url,
            "field": field_path,
            "sequence_confirmed": reflected,
            "confirmation_depth": if reflected { 2 } else { 1 },
            "env": OAST_BASE_ENV
        }))
        .with_remediation(
            "Restrict outbound network access for backend workers and enforce allowlists for user-controlled callback URLs.",
        ),
    );

    Ok(true)
}

fn collect_schema_operations(spec: &Value) -> Vec<SchemaOperation> {
    let mut operations = Vec::new();

    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        return operations;
    };

    for (path, item) in paths {
        let Some(item_obj) = item.as_object() else {
            continue;
        };

        for (method_name, operation) in item_obj {
            if !is_mutation_method(method_name) {
                continue;
            }
            let Some(method) = parse_http_method(method_name) else {
                continue;
            };
            let Some(operation_obj) = operation.as_object() else {
                continue;
            };
            let Some(schema) = extract_request_schema(operation_obj, spec) else {
                continue;
            };

            operations.push(SchemaOperation {
                method,
                method_name: method_name.to_ascii_uppercase(),
                path: path.to_string(),
                body_schema: schema,
                operation_id: operation_obj
                    .get("operationId")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
            });
        }
    }

    operations
}

fn extract_request_schema(operation: &Map<String, Value>, spec: &Value) -> Option<Value> {
    if let Some(request_body) = operation.get("requestBody") {
        let request_body = resolve_ref_value(request_body, spec);
        if let Some(content) = request_body.get("content").and_then(Value::as_object) {
            let mut preferred = None;
            for (content_type, value) in content {
                let lower = content_type.to_ascii_lowercase();
                if lower.contains("json") {
                    preferred = Some(value);
                    break;
                }
            }
            if preferred.is_none() {
                preferred = content.values().next();
            }
            if let Some(media) = preferred {
                let media = resolve_ref_value(media, spec);
                if let Some(schema) = media.get("schema") {
                    let schema = resolve_ref_value(schema, spec);
                    if schema.is_object() {
                        return Some(schema);
                    }
                }
            }
        }
    }

    if let Some(parameters) = operation.get("parameters").and_then(Value::as_array) {
        for parameter in parameters {
            let parameter = resolve_ref_value(parameter, spec);
            let Some(parameter_obj) = parameter.as_object() else {
                continue;
            };
            if parameter_obj
                .get("in")
                .and_then(Value::as_str)
                .map(|value| value.eq_ignore_ascii_case("body"))
                .unwrap_or(false)
            {
                if let Some(schema) = parameter_obj.get("schema") {
                    let schema = resolve_ref_value(schema, spec);
                    if schema.is_object() {
                        return Some(schema);
                    }
                }
            }
        }
    }

    None
}

fn resolve_ref_value(value: &Value, spec: &Value) -> Value {
    let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
        return value.clone();
    };

    if !reference.starts_with("#/") {
        return value.clone();
    }

    let pointer = reference.trim_start_matches('#');
    spec.pointer(pointer)
        .cloned()
        .unwrap_or_else(|| value.clone())
}

fn synthesize_payload(schema: &Value, spec: &Value, depth: usize) -> Option<Value> {
    if depth > 4 {
        return None;
    }

    let resolved = resolve_ref_value(schema, spec);

    if let Some(example) = resolved.get("example") {
        return Some(example.clone());
    }

    if let Some(enumeration) = resolved.get("enum").and_then(Value::as_array) {
        if let Some(first) = enumeration.first() {
            return Some(first.clone());
        }
    }

    if let Some(one_of) = resolved.get("oneOf").and_then(Value::as_array) {
        if let Some(first) = one_of.first() {
            return synthesize_payload(first, spec, depth + 1);
        }
    }

    if let Some(any_of) = resolved.get("anyOf").and_then(Value::as_array) {
        if let Some(first) = any_of.first() {
            return synthesize_payload(first, spec, depth + 1);
        }
    }

    if let Some(all_of) = resolved.get("allOf").and_then(Value::as_array) {
        let mut combined = Map::new();
        for sub_schema in all_of {
            if let Some(Value::Object(part)) = synthesize_payload(sub_schema, spec, depth + 1) {
                for (key, value) in part {
                    combined.insert(key, value);
                }
            }
        }
        if !combined.is_empty() {
            return Some(Value::Object(combined));
        }
    }

    match resolved.get("type").and_then(Value::as_str) {
        Some("object") => synthesize_object_payload(&resolved, spec, depth + 1),
        Some("array") => {
            let item = resolved
                .get("items")
                .and_then(|items| synthesize_payload(items, spec, depth + 1))
                .unwrap_or(Value::String("item".to_string()));
            Some(Value::Array(vec![item]))
        }
        Some("integer") => Some(Value::Number(1.into())),
        Some("number") => serde_json::Number::from_f64(1.0).map(Value::Number),
        Some("boolean") => Some(Value::Bool(true)),
        Some("string") => Some(Value::String(sample_string_value(&resolved))),
        _ => {
            if resolved.get("properties").is_some() {
                synthesize_object_payload(&resolved, spec, depth + 1)
            } else {
                None
            }
        }
    }
}

fn synthesize_object_payload(schema: &Value, spec: &Value, depth: usize) -> Option<Value> {
    let properties = schema.get("properties").and_then(Value::as_object);

    let mut object = Map::new();

    if let Some(properties) = properties {
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();

        for (index, (name, prop_schema)) in properties.iter().enumerate() {
            if !required.is_empty() && !required.contains(name.as_str()) {
                continue;
            }
            if required.is_empty() && index >= 3 {
                break;
            }
            if let Some(value) = synthesize_payload(prop_schema, spec, depth + 1) {
                object.insert(name.clone(), value);
            }
        }
    }

    if object.is_empty() {
        object.insert("value".to_string(), Value::String("apihunter".to_string()));
    }

    Some(Value::Object(object))
}

fn sample_string_value(schema: &Value) -> String {
    if let Some(default) = schema.get("default").and_then(Value::as_str) {
        return default.to_string();
    }

    match schema.get("format").and_then(Value::as_str) {
        Some("email") => "user@example.com".to_string(),
        Some("uuid") => "00000000-0000-4000-8000-000000000001".to_string(),
        Some("uri") | Some("url") => "https://example.com/callback".to_string(),
        _ => "apihunter".to_string(),
    }
}

fn build_schema_fuzz_variants(payload: &Value) -> Vec<ProbeVariant> {
    let mut variants = Vec::new();
    let mut dedup = HashSet::new();

    if let Some(mutated) = replace_first_string(payload, STRING_INJECTION_PAYLOAD) {
        let key = mutated.to_string();
        if dedup.insert(key) {
            variants.push(ProbeVariant {
                name: "string-injection",
                payload: mutated,
            });
        }
    }

    if let Some(mutated) = replace_first_number(payload, Value::String("not-a-number".to_string()))
    {
        let key = mutated.to_string();
        if dedup.insert(key) {
            variants.push(ProbeVariant {
                name: "number-type-confusion",
                payload: mutated,
            });
        }
    }

    if let Some(mutated) = replace_first_bool(payload, Value::String("true".to_string())) {
        let key = mutated.to_string();
        if dedup.insert(key) {
            variants.push(ProbeVariant {
                name: "boolean-type-confusion",
                payload: mutated,
            });
        }
    }

    variants
}

fn replace_first_string(value: &Value, replacement: &str) -> Option<Value> {
    let mut cloned = value.clone();
    if replace_first_string_in_place(&mut cloned, replacement) {
        Some(cloned)
    } else {
        None
    }
}

fn replace_first_string_in_place(value: &mut Value, replacement: &str) -> bool {
    match value {
        Value::String(current) => {
            *current = replacement.to_string();
            true
        }
        Value::Array(values) => values
            .iter_mut()
            .any(|entry| replace_first_string_in_place(entry, replacement)),
        Value::Object(map) => map
            .iter_mut()
            .any(|(_, entry)| replace_first_string_in_place(entry, replacement)),
        _ => false,
    }
}

fn replace_first_number(value: &Value, replacement: Value) -> Option<Value> {
    let mut cloned = value.clone();
    if replace_first_number_in_place(&mut cloned, &replacement) {
        Some(cloned)
    } else {
        None
    }
}

fn replace_first_number_in_place(value: &mut Value, replacement: &Value) -> bool {
    match value {
        Value::Number(_) => {
            *value = replacement.clone();
            true
        }
        Value::Array(values) => values
            .iter_mut()
            .any(|entry| replace_first_number_in_place(entry, replacement)),
        Value::Object(map) => map
            .iter_mut()
            .any(|(_, entry)| replace_first_number_in_place(entry, replacement)),
        _ => false,
    }
}

fn replace_first_bool(value: &Value, replacement: Value) -> Option<Value> {
    let mut cloned = value.clone();
    if replace_first_bool_in_place(&mut cloned, &replacement) {
        Some(cloned)
    } else {
        None
    }
}

fn replace_first_bool_in_place(value: &mut Value, replacement: &Value) -> bool {
    match value {
        Value::Bool(_) => {
            *value = replacement.clone();
            true
        }
        Value::Array(values) => values
            .iter_mut()
            .any(|entry| replace_first_bool_in_place(entry, replacement)),
        Value::Object(map) => map
            .iter_mut()
            .any(|(_, entry)| replace_first_bool_in_place(entry, replacement)),
        _ => false,
    }
}

fn is_suspicious_fuzz_response(baseline: &HttpResponse, variant: &HttpResponse) -> bool {
    (variant.status >= 500 && baseline.status < 500)
        || (contains_error_marker(&variant.body) && !contains_error_marker(&baseline.body))
}

fn contains_error_marker(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    RESPONSE_ERROR_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn should_race_probe(operation: &SchemaOperation) -> bool {
    matches!(operation.method, Method::POST | Method::PUT | Method::PATCH)
        && path_contains_sensitive_keyword(&operation.path, RACE_SENSITIVE_KEYWORDS)
}

fn path_contains_sensitive_keyword(path: &str, keywords: &[&str]) -> bool {
    let lower = path.to_ascii_lowercase();
    lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|segment| !segment.is_empty() && keywords.contains(&segment))
}

fn race_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let Ok(value) = HeaderValue::from_str(token) {
        headers.insert(HeaderName::from_static("idempotency-key"), value);
    }
    if let Ok(value) = HeaderValue::from_str(token) {
        headers.insert(HeaderName::from_static("x-apihunter-race-token"), value);
    }

    headers
}

fn correlation_token(kind: &str, path: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    let path_fragment = path
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(18)
        .collect::<String>()
        .to_ascii_lowercase();

    format!("apihunter-{kind}-{path_fragment}-{millis}")
}

fn inject_oast_callback(payload: &Value, callback_url: &str) -> Option<(String, Value)> {
    let mut cloned = payload.clone();
    let mut path = String::new();

    if inject_oast_in_place(&mut cloned, callback_url, "$", &mut path) {
        Some((path, cloned))
    } else {
        None
    }
}

fn inject_oast_in_place(
    value: &mut Value,
    callback_url: &str,
    current_path: &str,
    chosen_path: &mut String,
) -> bool {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let next_path = format!("{current_path}.{key}");
                if child.is_string() && is_oast_candidate_key(key) {
                    *child = Value::String(callback_url.to_string());
                    *chosen_path = next_path;
                    return true;
                }
                if inject_oast_in_place(child, callback_url, &next_path, chosen_path) {
                    return true;
                }
            }
            false
        }
        Value::Array(values) => {
            for (index, child) in values.iter_mut().enumerate() {
                let next_path = format!("{current_path}[{index}]");
                if inject_oast_in_place(child, callback_url, &next_path, chosen_path) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn is_oast_candidate_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    OAST_FIELD_KEYWORDS
        .iter()
        .any(|keyword| lower.contains(keyword))
}

fn materialize_operation_url(seed_url: &str, spec: &Value, operation_path: &str) -> Option<String> {
    let materialized_path = materialize_path_template(operation_path);

    if let Some(server_base) = resolve_server_base_url(seed_url, spec) {
        return join_base_and_path(&server_base, &materialized_path);
    }

    let seed = Url::parse(seed_url).ok()?;
    let origin = format!("{}://{}", seed.scheme(), seed.host_str()?);
    let origin = if let Some(port) = seed.port() {
        format!("{origin}:{port}")
    } else {
        origin
    };

    let base = Url::parse(&origin).ok()?;
    join_base_and_path(&base, &materialized_path)
}

fn resolve_server_base_url(seed_url: &str, spec: &Value) -> Option<Url> {
    if let Some(servers) = spec.get("servers").and_then(Value::as_array) {
        for server in servers {
            if let Some(url_value) = server.get("url").and_then(Value::as_str) {
                if let Ok(absolute) = Url::parse(url_value) {
                    return Some(absolute);
                }
                if let Ok(seed) = Url::parse(seed_url) {
                    if let Ok(relative) = seed.join(url_value) {
                        return Some(relative);
                    }
                }
            }
        }
    }

    let host = spec.get("host").and_then(Value::as_str)?;
    let scheme = spec
        .get("schemes")
        .and_then(Value::as_array)
        .and_then(|schemes| schemes.first())
        .and_then(Value::as_str)
        .unwrap_or("https");
    let base_path = spec.get("basePath").and_then(Value::as_str).unwrap_or("/");

    Url::parse(&format!("{scheme}://{host}{base_path}")).ok()
}

fn join_base_and_path(base: &Url, path: &str) -> Option<String> {
    let mut joinable = base.clone();
    if !joinable.path().ends_with('/') {
        let joined_path = format!("{}/", joinable.path().trim_end_matches('/'));
        joinable.set_path(&joined_path);
    }

    joinable
        .join(path.trim_start_matches('/'))
        .ok()
        .map(|u| u.to_string())
}

fn materialize_path_template(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut in_parameter = false;

    for ch in path.chars() {
        if ch == '{' {
            in_parameter = true;
            if !out.ends_with('/') {
                out.push('/');
            }
            out.push('1');
            continue;
        }
        if ch == '}' {
            in_parameter = false;
            continue;
        }
        if !in_parameter {
            out.push(ch);
        }
    }

    if out.is_empty() {
        "/".to_string()
    } else {
        out
    }
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace"
    )
}

fn is_mutation_method(method: &str) -> bool {
    matches!(method, "post" | "put" | "patch" | "delete")
}

fn parse_http_method(method: &str) -> Option<Method> {
    match method {
        "get" => Some(Method::GET),
        "post" => Some(Method::POST),
        "put" => Some(Method::PUT),
        "patch" => Some(Method::PATCH),
        "delete" => Some(Method::DELETE),
        "head" => Some(Method::HEAD),
        "options" => Some(Method::OPTIONS),
        "trace" => Some(Method::TRACE),
        _ => None,
    }
}

fn looks_like_file_upload(op_obj: &serde_json::Map<String, Value>) -> bool {
    if let Some(req) = op_obj.get("requestBody") {
        if let Some(content) = req.get("content").and_then(|v| v.as_object()) {
            for key in content.keys() {
                let ct = key.to_ascii_lowercase();
                if ct.contains("multipart/form-data") || ct.contains("application/octet-stream") {
                    return true;
                }
            }
        }
    }

    if let Some(params) = op_obj.get("parameters").and_then(|v| v.as_array()) {
        for p in params {
            if let Some(obj) = p.as_object() {
                let loc = obj.get("in").and_then(|v| v.as_str()).unwrap_or("");
                let typ = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if loc == "formData" && typ == "file" {
                    return true;
                }
            }
        }
    }

    false
}
