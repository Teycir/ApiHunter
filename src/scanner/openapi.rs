// src/scanner/openapi.rs
//
// OpenAPI / Swagger spec security analysis.

use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Severity},
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

#[async_trait]
impl Scanner for OpenApiScanner {
    fn name(&self) -> &'static str {
        "openapi"
    }

    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        _config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();

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
                Ok(spec) => analyze_spec(&spec_url, &spec, &mut findings),
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
        serde_yaml::from_str::<Value>(trimmed).map_err(|e| e.to_string())
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

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace"
    )
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
