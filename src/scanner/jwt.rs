// src/scanner/jwt.rs
//
// JWT-specific security checks.

use std::collections::HashSet;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use sha2::Sha256;
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::{Finding, Severity},
};

use super::Scanner;

type HmacSha256 = Hmac<Sha256>;

static JWT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
        .unwrap());

static SENSITIVE_CLAIMS: &[&str] = &[
    "email",
    "role",
    "roles",
    "is_admin",
    "admin",
    "permissions",
    "scope",
];

const LONG_LIVED_SECS: i64 = 60 * 60 * 24 * 30; // 30 days

pub struct JwtScanner;

impl JwtScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for JwtScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        _config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let resp = match client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                return (findings, errors);
            }
        };

        let mut seen = HashSet::new();
        for m in JWT_RE.find_iter(&resp.body) {
            let token = m.as_str().to_string();
            if !seen.insert(token.clone()) {
                continue;
            }

            analyze_jwt(url, &token, &mut findings);
        }

        (findings, errors)
    }
}

fn analyze_jwt(url: &str, token: &str, findings: &mut Vec<Finding>) {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }

    let header = decode_json(parts[0]);
    let payload = decode_json(parts[1]);
    let signature = decode_segment(parts[2]);

    let alg = header
        .as_ref()
        .and_then(|h| h.get("alg"))
        .and_then(Value::as_str)
        .unwrap_or("");

    if alg.eq_ignore_ascii_case("none") {
        findings.push(
            Finding::new(
                url,
                "jwt/alg-none",
                "JWT uses alg=none",
                Severity::Critical,
                "JWTs signed with alg=none can be forged without a secret key.",
                "jwt",
            )
            .with_evidence(format!("Token: {}", redact_token(token)))
            .with_remediation(
                "Disallow alg=none and enforce signature verification with a strong key.",
            ),
        );
    }

    if let Some(payload) = &payload {
        let mut hits = Vec::new();
        for key in SENSITIVE_CLAIMS {
            if payload.get(*key).is_some() {
                hits.push(*key);
            }
        }

        if !hits.is_empty() {
            findings.push(
                Finding::new(
                    url,
                    "jwt/sensitive-claims",
                    "JWT contains sensitive claims",
                    Severity::Medium,
                    format!(
                        "JWT payload exposes potentially sensitive claims: {}",
                        hits.join(", ")
                    ),
                    "jwt",
                )
                .with_evidence(format!("Token: {}", redact_token(token)))
                .with_remediation(
                    "Minimize sensitive data in JWTs and prefer opaque tokens when possible.",
                ),
            );
        }

        match payload.get("exp").and_then(Value::as_i64) {
            Some(exp) => {
                let now = Utc::now().timestamp();
                if exp - now > LONG_LIVED_SECS {
                    findings.push(
                        Finding::new(
                            url,
                            "jwt/long-lived",
                            "JWT has a long expiration window",
                            Severity::Medium,
                            "JWT expiration is far in the future; long-lived tokens increase risk if leaked.",
                            "jwt",
                        )
                        .with_evidence(format!("exp: {exp}, now: {now}"))
                        .with_remediation(
                            "Use short-lived access tokens and rotate/refresh them frequently.",
                        ),
                    );
                }
            }
            None => {
                findings.push(
                    Finding::new(
                        url,
                        "jwt/no-exp",
                        "JWT missing exp claim",
                        Severity::Medium,
                        "JWT has no exp claim; tokens without expiration increase risk if leaked.",
                        "jwt",
                    )
                    .with_evidence(format!("Token: {}", redact_token(token)))
                    .with_remediation(
                        "Include a short-lived exp claim and rotate tokens regularly.",
                    ),
                );
            }
        }
    }

    if alg.eq_ignore_ascii_case("hs256") {
        if let Some(sig) = signature {
            if let Some(secret) = weak_secret_match(url, parts[0], parts[1], &sig) {
                findings.push(
                    Finding::new(
                        url,
                        "jwt/weak-secret",
                        "JWT signed with weak HS256 secret",
                        Severity::Critical,
                        format!(
                            "JWT signature verifies with a weak secret candidate: '{secret}'.",
                        ),
                        "jwt",
                    )
                    .with_evidence(format!("Token: {}", redact_token(token)))
                    .with_remediation(
                        "Use a strong, high-entropy secret for HS256 or move to asymmetric signing (RS256/ES256).",
                    ),
                );
            }
        }
    }
}

fn decode_segment(seg: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(seg).ok()
}

fn decode_json(seg: &str) -> Option<Value> {
    let bytes = decode_segment(seg)?;
    serde_json::from_slice(&bytes).ok()
}

fn weak_secret_match(url: &str, header_b64: &str, payload_b64: &str, sig: &[u8]) -> Option<String> {
    let mut candidates = vec![
        "secret",
        "password",
        "changeme",
        "admin",
        "jwt",
        "token",
        "test",
        "example",
        "default",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect::<Vec<_>>();

    if let Ok(parsed) = Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            candidates.push(host.to_string());
            if let Some(root) = host.split('.').next() {
                if !root.is_empty() {
                    candidates.push(root.to_string());
                }
            }
        }
    }

    let signing_input = format!("{header_b64}.{payload_b64}");

    for secret in candidates {
        if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
            mac.update(signing_input.as_bytes());
            if mac.verify_slice(sig).is_ok() {
                return Some(secret);
            }
        }
    }

    None
}

fn redact_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 16 {
        return token.to_string();
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 8..].iter().collect();
    format!("{head}…{tail}")
}
