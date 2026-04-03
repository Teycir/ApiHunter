use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashSet;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method,
};
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Confidence, Finding, Severity},
};

use super::Scanner;

const GRPC_CT_HINTS: &[&str] = &["application/grpc", "application/grpc-web"];
const PROTOBUF_CT_HINTS: &[&str] = &["application/x-protobuf", "application/protobuf"];
const GRPC_REFLECTION_PATHS: &[&str] = &[
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/grpc.health.v1.Health/Check",
];
const GRPC_PATH_HINTS: &[&str] = &["grpc", "protobuf", ".proto"];

pub struct GrpcProtobufScanner {
    active_probe_hosts: Arc<DashSet<String>>,
}

impl GrpcProtobufScanner {
    pub fn new(_config: &Config) -> Self {
        Self {
            active_probe_hosts: Arc::new(DashSet::new()),
        }
    }
}

#[async_trait]
impl Scanner for GrpcProtobufScanner {
    fn name(&self) -> &'static str {
        "grpc_protobuf"
    }

    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let baseline = match client.get(url).await {
            Ok(response) => response,
            Err(error) => {
                errors.push(error);
                return (findings, errors);
            }
        };

        let ct = baseline
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();

        let grpc_header_present = baseline.header("grpc-status").is_some()
            || baseline.header("grpc-message").is_some()
            || baseline.header("x-grpc-web").is_some();
        let grpc_ct_present = GRPC_CT_HINTS.iter().any(|hint| ct.contains(hint));
        if grpc_ct_present || grpc_header_present {
            findings.push(
                Finding::new(
                    url,
                    "grpc_protobuf/grpc-transport-detected",
                    "gRPC transport signal detected",
                    Severity::Info,
                    "Response headers/content-type suggest this endpoint is served by gRPC or gRPC-Web.",
                    "grpc_protobuf",
                )
                .with_evidence(grpc_transport_evidence(&baseline))
                .with_confidence(Confidence::Medium)
                .with_remediation(
                    "Apply explicit authn/authz and method-level ACL checks on gRPC handlers and gateway bridges.",
                ),
            );
        }

        let protobuf_ct_present = PROTOBUF_CT_HINTS.iter().any(|hint| ct.contains(hint));
        let protobuf_path_hint = url
            .to_ascii_lowercase()
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.')
            .any(|segment| GRPC_PATH_HINTS.contains(&segment));
        if protobuf_ct_present || protobuf_path_hint {
            findings.push(
                Finding::new(
                    url,
                    "grpc_protobuf/protobuf-signal-detected",
                    "Protobuf surface signal detected",
                    Severity::Low,
                    "Endpoint appears to expose protobuf/gRPC-oriented content or routing hints.",
                    "grpc_protobuf",
                )
                .with_evidence(format!(
                    "content-type={} | path={}",
                    baseline.header("content-type").unwrap_or(""),
                    url
                ))
                .with_confidence(Confidence::Low)
                .with_remediation(
                    "Review protobuf service exposure and ensure external routing only allows intended RPC methods.",
                ),
            );
        }

        if config.active_checks {
            if let Some(host_key) = host_key(url) {
                if self.active_probe_hosts.insert(host_key) {
                    run_grpc_active_probe(url, client, &mut findings, &mut errors).await;
                }
            }
        }

        (findings, errors)
    }
}

async fn run_grpc_active_probe(
    url: &str,
    client: &HttpClient,
    findings: &mut Vec<Finding>,
    errors: &mut Vec<CapturedError>,
) {
    let Some(origin) = origin(url) else {
        return;
    };

    for path in GRPC_REFLECTION_PATHS {
        let probe_url = format!("{origin}{path}");
        let response = match client
            .request(Method::POST, &probe_url, Some(grpc_probe_headers()), None)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };

        let ct = response
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let grpc_status = response.header("grpc-status").unwrap_or("");
        let looks_grpc = GRPC_CT_HINTS.iter().any(|hint| ct.contains(hint))
            || !grpc_status.is_empty()
            || response.header("grpc-message").is_some();

        if !looks_grpc {
            continue;
        }

        findings.push(
            Finding::new(
                &probe_url,
                "grpc_protobuf/grpc-reflection-or-health-surface",
                "Potential gRPC reflection/health endpoint surface detected",
                Severity::Medium,
                "Known gRPC reflection/health probe path returned gRPC-like response metadata.",
                "grpc_protobuf",
            )
            .with_evidence(format!(
                "path={} | status={} | content-type={} | grpc-status={}",
                path,
                response.status,
                response.header("content-type").unwrap_or(""),
                grpc_status
            ))
            .with_confidence(Confidence::Medium)
            .with_metadata(serde_json::json!({
                "sequence_confirmed": true,
                "confirmation_depth": 1,
                "probe_path": path,
            }))
            .with_remediation(
                "Restrict reflection/health RPC exposure to trusted networks and enforce transport-level authentication where applicable.",
            ),
        );
        break;
    }
}

fn grpc_transport_evidence(response: &crate::http_client::HttpResponse) -> String {
    let mut lines = Vec::new();
    if let Some(value) = response.header("content-type") {
        lines.push(format!("content-type: {value}"));
    }
    if let Some(value) = response.header("grpc-status") {
        lines.push(format!("grpc-status: {value}"));
    }
    if let Some(value) = response.header("grpc-message") {
        lines.push(format!("grpc-message: {value}"));
    }
    if let Some(value) = response.header("x-grpc-web") {
        lines.push(format!("x-grpc-web: {value}"));
    }
    lines.join(" | ")
}

fn grpc_probe_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/grpc"),
    );
    headers.insert(
        HeaderName::from_static("te"),
        HeaderValue::from_static("trailers"),
    );
    headers.insert(
        HeaderName::from_static("x-apihunter-grpc-probe"),
        HeaderValue::from_static("1"),
    );
    headers
}

fn host_key(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "0".to_string());
    Some(format!("{host}:{port}"))
}

fn origin(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let base = format!("{}://{}", parsed.scheme(), host);
    Some(if let Some(port) = parsed.port() {
        format!("{base}:{port}")
    } else {
        base
    })
}
