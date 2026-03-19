use async_trait::async_trait;
use base64::Engine as _;
use rand::{seq::SliceRandom, RngCore};
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Severity},
};

use super::Scanner;

pub struct WebSocketScanner;

impl WebSocketScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

static WS_PATHS: &[&str] = &[
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io/?EIO=4&transport=websocket",
    "/graphql",
];

fn random_cross_origin_probe() -> &'static str {
    const ORIGINS: &[&str] = &[
        "https://app.example.net",
        "https://cdn.example.net",
        "https://portal.example.org",
    ];
    let mut rng = rand::thread_rng();
    ORIGINS
        .choose(&mut rng)
        .copied()
        .unwrap_or("https://app.example.net")
}

#[async_trait]
impl Scanner for WebSocketScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        if !config.active_checks {
            return (Vec::new(), Vec::new());
        }

        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let Some((same_origin, candidates)) = websocket_candidates(url) else {
            return (findings, errors);
        };

        for candidate in candidates {
            let same_origin_resp = match websocket_probe(client, &candidate, &same_origin).await {
                Ok(resp) => resp,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };

            if !is_upgrade_success(&same_origin_resp) {
                continue;
            }

            findings.push(
                Finding::new(
                    &candidate,
                    "websocket/upgrade-endpoint",
                    "WebSocket endpoint accepts upgrade",
                    Severity::Info,
                    "Endpoint accepted a WebSocket upgrade handshake.",
                    "websocket",
                )
                .with_evidence(format!(
                    "GET {candidate}\nOrigin: {same_origin}\nStatus: {}",
                    same_origin_resp.status
                ))
                .with_remediation(
                    "Ensure this endpoint enforces authentication and strict message-level authorization.",
                ),
            );

            let cross_origin = random_cross_origin_probe();
            match websocket_probe(client, &candidate, cross_origin).await {
                Ok(resp) if is_upgrade_success(&resp) => {
                    findings.push(
                        Finding::new(
                            &candidate,
                            "websocket/origin-not-validated",
                            "WebSocket origin validation may be missing",
                            Severity::Medium,
                            "Endpoint accepted WebSocket upgrades for a cross-origin request.",
                            "websocket",
                        )
                        .with_evidence(format!(
                            "GET {candidate}\nOrigin: {cross_origin}\nStatus: {}\nSec-WebSocket-Accept: {}",
                            resp.status,
                            resp.header("sec-websocket-accept").unwrap_or("-")
                        ))
                        .with_remediation(
                            "Validate the Origin header against an allowlist and reject untrusted origins.",
                        ),
                    );
                }
                Ok(_) => {}
                Err(e) => errors.push(e),
            }
        }

        (findings, errors)
    }
}

fn websocket_candidates(seed: &str) -> Option<(String, Vec<String>)> {
    let parsed = Url::parse(seed).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }

    let host = parsed.host_str()?;
    let mut origin = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }

    let mut base = origin.clone();
    if base.ends_with('/') {
        base.pop();
    }

    let mut candidates = Vec::new();
    for path in WS_PATHS {
        candidates.push(format!("{base}{path}"));
    }

    let seed_lower = parsed.path().to_ascii_lowercase();
    if seed_lower.contains("ws") || seed_lower.contains("socket") {
        candidates.push(seed.to_string());
    }

    candidates.sort();
    candidates.dedup();
    if candidates.len() > 1 {
        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
    }

    Some((origin, candidates))
}

async fn websocket_probe(
    client: &HttpClient,
    url: &str,
    origin: &str,
) -> Result<crate::http_client::HttpResponse, CapturedError> {
    let mut key_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let ws_key = base64::engine::general_purpose::STANDARD.encode(key_bytes);

    let headers = vec![
        ("Connection".to_string(), "Upgrade".to_string()),
        ("Upgrade".to_string(), "websocket".to_string()),
        ("Sec-WebSocket-Version".to_string(), "13".to_string()),
        ("Sec-WebSocket-Key".to_string(), ws_key),
        ("Origin".to_string(), origin.to_string()),
    ];

    client.get_with_headers(url, &headers).await
}

fn is_upgrade_success(resp: &crate::http_client::HttpResponse) -> bool {
    if resp.status == 101 {
        return true;
    }

    resp.header("sec-websocket-accept").is_some()
}
