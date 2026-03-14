// src/scanner/jwt.rs
//
// JWT-specific security checks.

use std::collections::HashSet;

use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
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
    Lazy::new(|| Regex::new(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+").unwrap());

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

static WEAK_SECRET_LIST: Lazy<Vec<String>> = Lazy::new(|| {
    include_str!("../../assets/jwt_secrets.txt")
        .lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
});

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
        config: &Config,
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
        let baseline_status = resp.status;

        let mut seen = HashSet::new();

        // Scan response headers for JWTs (common in Set-Cookie or auth headers).
        for (header_name, header_value) in &resp.headers {
            if matches!(
                header_name.as_str(),
                "set-cookie" | "authorization" | "x-auth-token" | "x-access-token" | "x-id-token"
            ) {
                for m in JWT_RE.find_iter(header_value) {
                    let token = m.as_str().to_string();
                    if seen.insert(token.clone()) {
                        analyze_jwt(
                            url,
                            &token,
                            client,
                            config,
                            baseline_status,
                            &mut findings,
                            &mut errors,
                        )
                        .await;
                    }
                }
            }
        }

        let ct = resp
            .headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        let scannable = ct.is_empty()
            || ct.contains("json")
            || ct.contains("text/")
            || ct.contains("javascript")
            || ct.contains("xml");
        if !scannable {
            return (findings, errors);
        }

        for m in JWT_RE.find_iter(&resp.body) {
            let token = m.as_str().to_string();
            if !seen.insert(token.clone()) {
                continue;
            }

            analyze_jwt(
                url,
                &token,
                client,
                config,
                baseline_status,
                &mut findings,
                &mut errors,
            )
            .await;
        }

        (findings, errors)
    }
}

async fn analyze_jwt(
    url: &str,
    token: &str,
    client: &HttpClient,
    config: &Config,
    baseline_status: u16,
    findings: &mut Vec<Finding>,
    _errors: &mut Vec<CapturedError>,
) {
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

    // Suspicious kid patterns (path traversal / URL fetch).
    if let Some(kid) = header
        .as_ref()
        .and_then(|h| h.get("kid"))
        .and_then(Value::as_str)
    {
        if kid.contains("..")
            || kid.starts_with("http://")
            || kid.starts_with("https://")
            || kid.starts_with("file:")
        {
            findings.push(
                Finding::new(
                    url,
                    "jwt/suspicious-kid",
                    "JWT kid header looks suspicious",
                    Severity::Low,
                    "The JWT `kid` header contains a path or URL-like value. Some implementations\n                     load key material from filesystem/URLs and may be vulnerable to injection.",
                    "jwt",
                )
                .with_evidence(format!("kid: {kid}"))
                .with_remediation(
                    "Treat `kid` as an opaque identifier and disallow path/URL resolution.",
                ),
            );
        }
    }

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

    if config.active_checks && alg.eq_ignore_ascii_case("rs256") {
        if let Some(finding) =
            attempt_alg_confusion(url, header.as_ref(), parts[1], client, baseline_status).await
        {
            findings.push(finding);
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
    let mut candidates = WEAK_SECRET_LIST.clone();

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

async fn attempt_alg_confusion(
    url: &str,
    header: Option<&Value>,
    payload_b64: &str,
    client: &HttpClient,
    baseline_status: u16,
) -> Option<Finding> {
    let header = header?;

    // NOTE: For RS256->HS256 confusion, the HMAC key should be the raw public
    // key bytes (SPKI). We attempt a best-effort decode from x5c or jwk, but a
    // full, correct extraction requires certificate/JWK parsing.
    let secret = if let Some(x5c) = header.get("x5c").and_then(Value::as_array) {
        x5c.get(0)
            .and_then(Value::as_str)
            .and_then(|s| BASE64_STD.decode(s.as_bytes()).ok())
    } else if let Some(jwk) = header.get("jwk") {
        serde_json::to_string(jwk).ok().map(|s| s.into_bytes())
    } else {
        None
    }?;

    let mut new_header = header.clone();
    if let Some(obj) = new_header.as_object_mut() {
        obj.insert("alg".to_string(), Value::String("HS256".to_string()));
    }

    let header_json = serde_json::to_vec(&new_header).ok()?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);

    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut mac = HmacSha256::new_from_slice(&secret).ok()?;
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    let forged = format!("{header_b64}.{payload_b64}.{sig_b64}");
    let auth_header = format!("Bearer {forged}");

    let extra = vec![("Authorization".to_string(), auth_header)];
    let resp = client.get_with_headers(url, &extra).await.ok()?;

    if resp.status < 400 {
        return Some(
            Finding::new(
                url,
                "jwt/alg-confusion",
                "JWT RS256 -> HS256 confusion",
                Severity::Critical,
                "A forged HS256 token signed with a public key-like secret appears to be accepted.",
                "jwt",
            )
            .with_evidence(format!(
                "baseline_status: {baseline_status}, forged_status: {}",
                resp.status
            ))
            .with_remediation(
                "Reject HS256 tokens when using RS256 keys; ensure key type matches algorithm.",
            ),
        );
    }

    None
}
