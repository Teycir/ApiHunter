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

use super::{common::http_utils::is_json_content_type, Scanner};

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
    fn name(&self) -> &'static str {
        "jwt"
    }

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
            || is_json_content_type(ct)
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
    errors: &mut Vec<CapturedError>,
) {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }

    let header = match decode_json(parts[0]) {
        Some(v) => v,
        None => {
            errors.push(CapturedError::from_str(
                "jwt/decode",
                Some(url.to_string()),
                "Failed to decode JWT header segment as JSON",
            ));
            return;
        }
    };
    let payload = match decode_json(parts[1]) {
        Some(v) => v,
        None => {
            errors.push(CapturedError::from_str(
                "jwt/decode",
                Some(url.to_string()),
                "Failed to decode JWT payload segment as JSON",
            ));
            return;
        }
    };
    let signature = match decode_segment(parts[2]) {
        Some(v) => v,
        None => {
            errors.push(CapturedError::from_str(
                "jwt/decode",
                Some(url.to_string()),
                "Failed to decode JWT signature segment",
            ));
            return;
        }
    };

    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");

    // Suspicious kid patterns (path traversal / URL fetch).
    if let Some(kid) = header.get("kid").and_then(Value::as_str) {
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
                .with_remediation("Include a short-lived exp claim and rotate tokens regularly."),
            );
        }
    }

    if alg.eq_ignore_ascii_case("hs256") {
        let url_owned = url.to_string();
        let header_owned = parts[0].to_string();
        let payload_owned = parts[1].to_string();
        let signature_owned = signature.clone();
        match tokio::task::spawn_blocking(move || {
            weak_secret_match(&url_owned, &header_owned, &payload_owned, &signature_owned)
        })
        .await
        {
            Ok(Some(secret)) => {
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
            Ok(None) => {}
            Err(e) => errors.push(CapturedError::from_str(
                "jwt/weak_secret_probe",
                Some(url.to_string()),
                format!("weak-secret blocking task failed: {e}"),
            )),
        }
    }

    if config.active_checks && alg.eq_ignore_ascii_case("rs256") {
        if let Some(finding) = attempt_alg_confusion(
            url,
            Some(&header),
            parts[1],
            client,
            baseline_status,
            errors,
        )
        .await
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
    let mut host_candidates: Vec<String> = Vec::new();

    if let Ok(parsed) = Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            host_candidates.push(host.to_string());
            if let Some(root) = host.split('.').next() {
                if !root.is_empty() {
                    host_candidates.push(root.to_string());
                }
            }
        }
    }

    let signing_input = format!("{header_b64}.{payload_b64}");

    for secret in WEAK_SECRET_LIST
        .iter()
        .map(String::as_str)
        .chain(host_candidates.iter().map(String::as_str))
    {
        if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
            mac.update(signing_input.as_bytes());
            if mac.verify_slice(sig).is_ok() {
                return Some(secret.to_string());
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
    errors: &mut Vec<CapturedError>,
) -> Option<Finding> {
    let header = header?;
    let has_key_hint = header.get("x5c").is_some() || header.get("jwk").is_some();
    if !has_key_hint {
        return None;
    }

    // For RS256->HS256 confusion the forged HS256 token is signed with
    // attacker-controlled public key material. Try realistic encodings a
    // vulnerable verifier may consume from JWT hints (`jwk`/`x5c`).
    let secret_candidates = derive_alg_confusion_secrets(header);
    if secret_candidates.is_empty() {
        errors.push(CapturedError::from_str(
            "jwt/alg_confusion",
            Some(url.to_string()),
            "Unable to derive RSA key material from JWT header (expected valid jwk {kty,n,e} or x5c certificate)",
        ));
        return None;
    }

    let unauth_status = match client.get_without_auth(url).await {
        Ok(r) => Some(r.status),
        Err(mut e) => {
            e.context = "jwt/alg_confusion_baseline".to_string();
            errors.push(e);
            None
        }
    };

    for (secret_source, secret) in secret_candidates {
        let mut new_header = header.clone();
        if let Some(obj) = new_header.as_object_mut() {
            obj.insert("alg".to_string(), Value::String("HS256".to_string()));
        }

        let header_json = match serde_json::to_vec(&new_header) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json);

        let signing_input = format!("{header_b64}.{payload_b64}");
        let mut mac = match HmacSha256::new_from_slice(&secret) {
            Ok(m) => m,
            Err(_) => continue,
        };
        mac.update(signing_input.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        let forged = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let auth_header = format!("Bearer {forged}");

        let extra = vec![("Authorization".to_string(), auth_header)];
        let resp = match client.get_with_headers(url, &extra).await {
            Ok(r) => r,
            Err(mut e) => {
                e.message = format!("alg_confusion_probe[{secret_source}]: {}", e.message);
                errors.push(e);
                continue;
            }
        };

        if resp.status < 400 && matches!(unauth_status, Some(status) if status >= 400) {
            return Some(
                Finding::new(
                    url,
                    "jwt/alg-confusion",
                    "JWT RS256 -> HS256 confusion",
                    Severity::Critical,
                    "A forged HS256 token signed with derived public key material appears to be accepted.",
                    "jwt",
                )
                .with_evidence(format!(
                    "baseline_status: {baseline_status}, unauth_status: {}, forged_status: {}, key_source: {secret_source}",
                    unauth_status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    resp.status,
                ))
                .with_remediation(
                    "Reject HS256 tokens when using RS256 keys; ensure key type matches algorithm.",
                ),
            );
        }
    }

    None
}

fn derive_alg_confusion_secrets(header: &Value) -> Vec<(String, Vec<u8>)> {
    let mut candidates: Vec<(String, Vec<u8>)> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    let mut push_candidate = |label: &str, secret: Vec<u8>| {
        if secret.is_empty() {
            return;
        }
        if seen.insert(secret.clone()) {
            candidates.push((label.to_string(), secret));
        }
    };

    if let Some((modulus, exponent)) = header.get("jwk").and_then(extract_rsa_components_from_jwk) {
        if let Some(spki_der) = build_rsa_spki_der(&modulus, &exponent) {
            push_candidate("jwk-spki-der", spki_der.clone());
            push_candidate(
                "jwk-spki-pem",
                pem_encode("PUBLIC KEY", &spki_der).into_bytes(),
            );
        }
    }

    if let Some(x5c_der) = header
        .get("x5c")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_str)
        .and_then(|s| BASE64_STD.decode(s.as_bytes()).ok())
    {
        push_candidate("x5c-cert-der", x5c_der.clone());
        push_candidate(
            "x5c-cert-pem",
            pem_encode("CERTIFICATE", &x5c_der).into_bytes(),
        );

        if let Some(spki_der) = extract_subject_public_key_info_der_from_certificate(&x5c_der) {
            push_candidate("x5c-spki-der", spki_der.clone());
            push_candidate(
                "x5c-spki-pem",
                pem_encode("PUBLIC KEY", &spki_der).into_bytes(),
            );
        }
    }

    candidates
}

fn extract_rsa_components_from_jwk(jwk: &Value) -> Option<(Vec<u8>, Vec<u8>)> {
    let obj = jwk.as_object()?;
    let kty = obj.get("kty").and_then(Value::as_str).unwrap_or_default();
    if !kty.eq_ignore_ascii_case("RSA") {
        return None;
    }

    let n = obj.get("n").and_then(Value::as_str)?;
    let e = obj.get("e").and_then(Value::as_str)?;
    let mut modulus = URL_SAFE_NO_PAD.decode(n.as_bytes()).ok()?;
    let mut exponent = URL_SAFE_NO_PAD.decode(e.as_bytes()).ok()?;
    trim_leading_zeros(&mut modulus);
    trim_leading_zeros(&mut exponent);
    if modulus.is_empty() || exponent.is_empty() {
        return None;
    }
    Some((modulus, exponent))
}

fn trim_leading_zeros(bytes: &mut Vec<u8>) {
    if bytes.len() <= 1 {
        return;
    }
    let first_non_zero = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    if first_non_zero > 0 {
        bytes.drain(0..first_non_zero);
    }
}

fn build_rsa_spki_der(modulus: &[u8], exponent: &[u8]) -> Option<Vec<u8>> {
    let rsa_pkcs1 = build_rsa_pkcs1_der(modulus, exponent)?;
    let alg_id_value: Vec<u8> = vec![
        0x06, 0x09, // OBJECT IDENTIFIER length 9
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x01, // 1.2.840.113549.1.1.1 (rsaEncryption)
        0x05, 0x00, // NULL
    ];
    let alg_id = der_tlv(0x30, &alg_id_value);

    let mut bit_string = Vec::with_capacity(1 + rsa_pkcs1.len());
    bit_string.push(0x00); // unused bits
    bit_string.extend_from_slice(&rsa_pkcs1);
    let subject_public_key = der_tlv(0x03, &bit_string);

    let mut spki_value = Vec::with_capacity(alg_id.len() + subject_public_key.len());
    spki_value.extend_from_slice(&alg_id);
    spki_value.extend_from_slice(&subject_public_key);
    Some(der_tlv(0x30, &spki_value))
}

fn build_rsa_pkcs1_der(modulus: &[u8], exponent: &[u8]) -> Option<Vec<u8>> {
    if modulus.is_empty() || exponent.is_empty() {
        return None;
    }

    let modulus_tlv = der_integer(modulus);
    let exponent_tlv = der_integer(exponent);

    let mut value = Vec::with_capacity(modulus_tlv.len() + exponent_tlv.len());
    value.extend_from_slice(&modulus_tlv);
    value.extend_from_slice(&exponent_tlv);
    Some(der_tlv(0x30, &value))
}

fn der_integer(raw: &[u8]) -> Vec<u8> {
    let mut v = raw.to_vec();
    trim_leading_zeros(&mut v);
    if v.is_empty() {
        v.push(0);
    }
    if (v[0] & 0x80) != 0 {
        v.insert(0, 0x00);
    }
    der_tlv(0x02, &v)
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + value.len() + 5);
    out.push(tag);
    out.extend_from_slice(&der_len(value.len()));
    out.extend_from_slice(value);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut n = len;
    while n > 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(0x80 | (bytes.len() as u8));
    out.extend_from_slice(&bytes);
    out
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = BASE64_STD.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(String::from_utf8_lossy(chunk).as_ref());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn extract_subject_public_key_info_der_from_certificate(cert_der: &[u8]) -> Option<Vec<u8>> {
    if let Some(spki) = extract_spki_from_x509_layout(cert_der) {
        return Some(spki);
    }
    extract_spki_sequence_recursive(cert_der, 0)
}

fn extract_spki_from_x509_layout(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (cert_tag, cert_value_start, cert_value_end, _) = parse_der_tlv(cert_der, 0)?;
    if cert_tag != 0x30 {
        return None;
    }
    let cert_seq = &cert_der[cert_value_start..cert_value_end];

    let (tbs_tag, tbs_value_start, tbs_value_end, _) = parse_der_tlv(cert_seq, 0)?;
    if tbs_tag != 0x30 {
        return None;
    }
    let tbs = &cert_seq[tbs_value_start..tbs_value_end];

    let mut idx = 0usize;
    let (first_tag, _, _, next_idx) = parse_der_tlv(tbs, idx)?;
    if first_tag == 0xA0 {
        idx = next_idx;
    }

    // serialNumber, signature, issuer, validity, subject
    for _ in 0..5 {
        let (_, _, _, next) = parse_der_tlv(tbs, idx)?;
        idx = next;
    }

    let (spki_tag, _, _, spki_next) = parse_der_tlv(tbs, idx)?;
    if spki_tag != 0x30 {
        return None;
    }

    Some(tbs[idx..spki_next].to_vec())
}

fn extract_spki_sequence_recursive(input: &[u8], offset: usize) -> Option<Vec<u8>> {
    if offset >= input.len() {
        return None;
    }

    let (tag, value_start, value_end, next) = parse_der_tlv(input, offset)?;

    if tag == 0x30 && looks_like_spki_sequence(&input[value_start..value_end]) {
        return Some(input[offset..next].to_vec());
    }

    // Recurse into constructed values.
    if (tag & 0x20) != 0 {
        if let Some(found) = extract_spki_sequence_recursive(&input[value_start..value_end], 0) {
            return Some(found);
        }
    }

    // BIT STRING often wraps an encoded key structure. First octet is
    // "unused bits" count, then nested DER payload.
    if tag == 0x03 && value_start < value_end {
        let bit_payload = &input[value_start..value_end];
        if bit_payload.first() == Some(&0) && bit_payload.len() > 1 {
            if let Some(found) = extract_spki_sequence_recursive(&bit_payload[1..], 0) {
                return Some(found);
            }
        }
    }

    extract_spki_sequence_recursive(input, next)
}

fn looks_like_spki_sequence(seq_value: &[u8]) -> bool {
    let Some((alg_tag, _, _, alg_next)) = parse_der_tlv(seq_value, 0) else {
        return false;
    };
    if alg_tag != 0x30 {
        return false;
    }
    let Some((key_tag, _, _, key_next)) = parse_der_tlv(seq_value, alg_next) else {
        return false;
    };
    key_tag == 0x03 && key_next == seq_value.len()
}

fn parse_der_tlv(input: &[u8], offset: usize) -> Option<(u8, usize, usize, usize)> {
    if offset + 2 > input.len() {
        return None;
    }

    let tag = input[offset];
    let len_first = input[offset + 1];
    let mut len_idx = offset + 2;

    let len = if (len_first & 0x80) == 0 {
        len_first as usize
    } else {
        let nbytes = (len_first & 0x7f) as usize;
        if nbytes == 0 || nbytes > 4 || len_idx + nbytes > input.len() {
            return None;
        }
        let mut v = 0usize;
        for b in &input[len_idx..len_idx + nbytes] {
            v = (v << 8) | (*b as usize);
        }
        len_idx += nbytes;
        v
    };

    let value_start = len_idx;
    let value_end = value_start.checked_add(len)?;
    if value_end > input.len() {
        return None;
    }

    Some((tag, value_start, value_end, value_end))
}
