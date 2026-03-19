use async_trait::async_trait;
use rand::{distributions::Alphanumeric, seq::SliceRandom, Rng};
use reqwest::header::LOCATION;
use serde_json::Value;
use std::time::Duration;
use url::Url;

use crate::{
    config::Config,
    error::CapturedError,
    http_client::{HttpClient, HttpResponse},
    reports::{Finding, Severity},
};

use super::{common::http_utils::is_json_response, Scanner};

pub struct OAuthOidcScanner;

impl OAuthOidcScanner {
    pub fn new(_config: &Config) -> Self {
        Self
    }
}

static OAUTH_HINTS: &[&str] = &[
    "/oauth",
    "/oauth2",
    "/oidc",
    "/authorize",
    "/token",
    "/connect",
    "/.well-known/openid-configuration",
];

#[async_trait]
impl Scanner for OAuthOidcScanner {
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

        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return (findings, errors),
        };

        if !matches!(parsed.scheme(), "http" | "https") {
            return (findings, errors);
        }

        let path = parsed.path().to_ascii_lowercase();
        if !looks_oauth_related(&path) {
            return (findings, errors);
        }

        if is_authorize_like_path(&path) {
            let (mut f, mut e) = probe_authorize_redirect(url, config).await;
            findings.append(&mut f);
            errors.append(&mut e);
        }

        if let Some(well_known_url) = openid_well_known_url(&parsed) {
            let (mut f, mut e) = analyze_openid_metadata(url, &well_known_url, client).await;
            findings.append(&mut f);
            errors.append(&mut e);
        }

        (findings, errors)
    }
}

fn looks_oauth_related(path: &str) -> bool {
    OAUTH_HINTS.iter().any(|hint| path.contains(hint))
}

fn is_authorize_like_path(path: &str) -> bool {
    path.contains("authorize") || path.ends_with("/auth")
}

fn openid_well_known_url(parsed: &Url) -> Option<String> {
    let host = parsed.host_str()?;
    let mut base = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        base.push(':');
        base.push_str(&port.to_string());
    }
    Some(format!("{base}/.well-known/openid-configuration"))
}

fn random_probe_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .map(|c| c.to_ascii_lowercase())
        .take(len)
        .collect()
}

fn random_redirect_probe() -> String {
    const PROBES: &[&str] = &[
        "https://app.example.net/callback",
        "https://cdn.example.net/oauth/callback",
        "https://portal.example.org/auth/callback",
    ];
    let mut rng = rand::thread_rng();
    PROBES
        .choose(&mut rng)
        .copied()
        .unwrap_or("https://app.example.net/callback")
        .to_string()
}

async fn probe_authorize_redirect(
    target_url: &str,
    config: &Config,
) -> (Vec<Finding>, Vec<CapturedError>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let mut probe = match Url::parse(target_url) {
        Ok(u) => u,
        Err(_) => return (findings, errors),
    };
    probe.set_query(None);
    probe.set_fragment(None);

    let state_probe = format!("st_{}", random_probe_token(10));
    let client_probe = format!("apihunter-{}", random_probe_token(8));
    let redirect_probe = random_redirect_probe();

    probe
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_probe)
        .append_pair("redirect_uri", &redirect_probe)
        .append_pair("scope", "openid profile")
        .append_pair("state", &state_probe);

    let resp = match authorize_probe_without_redirects(config, &probe).await {
        Ok(r) => r,
        Err(e) => {
            errors.push(e);
            return (findings, errors);
        }
    };

    let Some(location) = resp.header("location") else {
        return (findings, errors);
    };
    let location_l = location.to_ascii_lowercase();

    if !location_l.starts_with(&redirect_probe) {
        return (findings, errors);
    }

    findings.push(
        Finding::new(
            target_url,
            "oauth/redirect-uri-not-validated",
            "OAuth authorize endpoint may accept attacker redirect_uri",
            Severity::High,
            "Authorization flow redirected to an attacker-controlled redirect_uri.",
            "oauth_oidc",
        )
        .with_evidence(format!(
            "GET {}\nStatus: {}\nLocation: {}",
            probe, resp.status, location
        ))
        .with_remediation(
            "Require exact redirect_uri matching per client registration and reject unregistered callbacks.",
        ),
    );

    if !location_l.contains(&format!("state={state_probe}")) {
        findings.push(
            Finding::new(
                target_url,
                "oauth/state-not-returned",
                "OAuth state parameter may not be round-tripped",
                Severity::Medium,
                "Authorization redirect did not include the supplied state value.",
                "oauth_oidc",
            )
            .with_evidence(format!(
                "GET {}\nStatus: {}\nLocation: {}",
                probe, resp.status, location
            ))
            .with_remediation(
                "Ensure the authorization server preserves and returns the exact state value.",
            ),
        );
    }

    (findings, errors)
}

async fn authorize_probe_without_redirects(
    config: &Config,
    probe: &Url,
) -> Result<HttpResponse, CapturedError> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(config.politeness.timeout_secs))
        .danger_accept_invalid_certs(config.danger_accept_invalid_certs);

    if let Some(proxy) = &config.proxy {
        match reqwest::Proxy::all(proxy) {
            Ok(p) => builder = builder.proxy(p),
            Err(e) => {
                return Err(CapturedError::new(
                    "oauth/authorize-probe",
                    Some(probe.to_string()),
                    &e,
                ));
            }
        }
    }

    let client = builder
        .build()
        .map_err(|e| CapturedError::new("oauth/authorize-probe", Some(probe.to_string()), &e))?;

    let resp =
        client.get(probe.as_str()).send().await.map_err(|e| {
            CapturedError::new("oauth/authorize-probe", Some(probe.to_string()), &e)
        })?;

    let mut headers = std::collections::HashMap::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), s.to_string());
        }
    }
    if let Some(loc) = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()) {
        headers.insert("location".to_string(), loc.to_string());
    }

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok(HttpResponse {
        status,
        headers,
        body,
        url: probe.to_string(),
    })
}

async fn analyze_openid_metadata(
    source_url: &str,
    metadata_url: &str,
    client: &HttpClient,
) -> (Vec<Finding>, Vec<CapturedError>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let body = if let Some(cached) = client.get_cached_spec(metadata_url) {
        cached
    } else {
        let resp = match client.get(metadata_url).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(e);
                return (findings, errors);
            }
        };

        if resp.status >= 400 || !is_json_response(&resp.headers, &resp.body) {
            return (findings, errors);
        }

        client.cache_spec(metadata_url, &resp.body);
        resp.body
    };

    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            errors.push(CapturedError::new(
                "oauth/openid-metadata-parse",
                Some(metadata_url.to_string()),
                &e,
            ));
            return (findings, errors);
        }
    };

    let pkce_methods = get_string_array(&parsed, "code_challenge_methods_supported");
    if pkce_methods.is_empty() {
        findings.push(
            Finding::new(
                source_url,
                "oauth/pkce-metadata-missing",
                "OIDC metadata missing PKCE methods",
                Severity::Medium,
                "OpenID metadata does not declare code_challenge_methods_supported.",
                "oauth_oidc",
            )
            .with_evidence(format!("GET {metadata_url}"))
            .with_remediation(
                "Publish code_challenge_methods_supported and enforce PKCE with S256 for public clients.",
            ),
        );
    } else {
        let has_s256 = pkce_methods.iter().any(|m| m == "s256");
        let has_plain = pkce_methods.iter().any(|m| m == "plain");

        if !has_s256 {
            findings.push(
                Finding::new(
                    source_url,
                    "oauth/pkce-s256-not-supported",
                    "OIDC metadata does not advertise PKCE S256",
                    Severity::High,
                    "Authorization server metadata does not include S256 in supported PKCE methods.",
                    "oauth_oidc",
                )
                .with_evidence(format!(
                    "GET {metadata_url}\ncode_challenge_methods_supported: {}",
                    pkce_methods.join(", ")
                ))
                .with_remediation(
                    "Support and require PKCE S256 for authorization-code flows.",
                ),
            );
        } else if has_plain {
            findings.push(
                Finding::new(
                    source_url,
                    "oauth/pkce-plain-supported",
                    "OIDC metadata allows weak PKCE plain method",
                    Severity::Medium,
                    "Authorization server metadata includes the weak PKCE plain method.",
                    "oauth_oidc",
                )
                .with_evidence(format!(
                    "GET {metadata_url}\ncode_challenge_methods_supported: {}",
                    pkce_methods.join(", ")
                ))
                .with_remediation("Disable PKCE plain and enforce S256 only."),
            );
        }
    }

    let response_types = get_string_array(&parsed, "response_types_supported");
    if response_types
        .iter()
        .any(|t| t.split_whitespace().any(|p| p == "token"))
    {
        findings.push(
            Finding::new(
                source_url,
                "oauth/implicit-flow-enabled",
                "OIDC metadata indicates implicit or hybrid token response types",
                Severity::Medium,
                "response_types_supported includes token-bearing flows.",
                "oauth_oidc",
            )
            .with_evidence(format!(
                "GET {metadata_url}\nresponse_types_supported: {}",
                response_types.join(", ")
            ))
            .with_remediation(
                "Prefer authorization-code + PKCE and disable implicit/hybrid token response types when possible.",
            ),
        );
    }

    let grant_types = get_string_array(&parsed, "grant_types_supported");
    if grant_types.iter().any(|g| g == "password") {
        findings.push(
            Finding::new(
                source_url,
                "oauth/ropc-grant-enabled",
                "OIDC metadata advertises password grant",
                Severity::Medium,
                "grant_types_supported includes Resource Owner Password Credentials.",
                "oauth_oidc",
            )
            .with_evidence(format!(
                "GET {metadata_url}\ngrant_types_supported: {}",
                grant_types.join(", ")
            ))
            .with_remediation(
                "Avoid password grant and migrate clients to authorization-code + PKCE.",
            ),
        );
    }

    (findings, errors)
}

fn get_string_array(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}
