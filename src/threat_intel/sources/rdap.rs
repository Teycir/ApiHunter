// src/threat_intel/sources/rdap.rs
//
// IANA RDAP domain registration probe — registrar, creation/expiry dates,
// nameservers, privacy-protected flag.
//
// Endpoint: https://rdap.org/domain/{domain}
// Auth:     none
// Notes:
//   - Only queried for domain targets (not raw IPs).
//   - A 404 means the domain is not found in RDAP; treated as empty result.

use crate::threat_intel::types::{RdapDomainData, SourceOutcome};
use std::time::Duration;

const SOURCE: &str = "rdap";

/// Minimal RDAP response shape — only the fields we score on.
#[derive(Debug, serde::Deserialize)]
struct RdapResponse {
    #[serde(rename = "ldhName", default)]
    ldh_name: Option<String>,
    #[serde(default)]
    entities: Vec<RdapEntity>,
    #[serde(rename = "nameservers", default)]
    nameservers: Vec<serde_json::Value>,
    #[serde(rename = "events", default)]
    events: Vec<RdapEvent>,
}

#[derive(Debug, serde::Deserialize)]
struct RdapEntity {
    roles: Vec<String>,
    #[serde(rename = "vcardArray", default)]
    vcard_array: Option<serde_json::Value>,
    #[serde(rename = "remarks", default)]
    remarks: Vec<RdapRemark>,
}

#[derive(Debug, serde::Deserialize)]
struct RdapRemark {
    #[serde(default)]
    description: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    event_action: String,
    #[serde(rename = "eventDate")]
    event_date: String,
}

pub async fn fetch(
    domain: &str,
    client: &reqwest::Client,
    timeout: Duration,
) -> SourceOutcome<RdapDomainData> {
    let url = format!("https://rdap.org/domain/{domain}");

    let result = tokio::time::timeout(
        timeout,
        client
            .get(&url)
            .header("Accept", "application/rdap+json, application/json")
            .send(),
    )
    .await;

    let resp = match result {
        Err(_) => {
            tracing::debug!(domain, source = SOURCE, "timeout");
            return SourceOutcome::Timeout;
        }
        Ok(Err(e)) => {
            tracing::debug!(domain, source = SOURCE, error = %e, "request error");
            return SourceOutcome::Error(e.to_string());
        }
        Ok(Ok(r)) => r,
    };

    if resp.status() == 404 {
        return SourceOutcome::Ok(RdapDomainData {
            domain: Some(domain.to_string()),
            ..Default::default()
        });
    }

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        tracing::debug!(domain, source = SOURCE, %status, "non-OK status");
        return SourceOutcome::Error(format!("HTTP {status}"));
    }

    let raw: RdapResponse = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(domain, source = SOURCE, error = %e, "parse error");
            return SourceOutcome::Error(e.to_string());
        }
    };

    let registrar = raw
        .entities
        .iter()
        .find(|e| e.roles.iter().any(|r| r == "registrar"))
        .and_then(|e| vcard_fn(e.vcard_array.as_ref()));

    let mut created: Option<String> = None;
    let mut expires: Option<String> = None;
    for ev in &raw.events {
        match ev.event_action.as_str() {
            "registration" => created = Some(ev.event_date.clone()),
            "expiration" => expires = Some(ev.event_date.clone()),
            _ => {}
        }
    }

    let nameservers: Vec<String> = raw
        .nameservers
        .iter()
        .filter_map(|ns| {
            ns.get("ldhName")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase())
        })
        .collect();

    let privacy_protected = raw.entities.iter().any(|e| {
        e.roles.iter().any(|r| r == "registrant")
            && (e.remarks.iter().any(|r| {
                r.description.iter().any(|d| {
                    let d = d.to_lowercase();
                    d.contains("privacy") || d.contains("redact") || d.contains("proxy")
                })
            }) || vcard_fn(e.vcard_array.as_ref())
                .map(|n| {
                    let n = n.to_lowercase();
                    n.contains("privacy") || n.contains("redact") || n.contains("proxy")
                })
                .unwrap_or(false))
    });

    SourceOutcome::Ok(RdapDomainData {
        domain: raw.ldh_name.or_else(|| Some(domain.to_string())),
        registrar,
        created,
        expires,
        nameservers,
        privacy_protected,
    })
}

fn vcard_fn(vcard: Option<&serde_json::Value>) -> Option<String> {
    let arr = vcard?.as_array()?;
    let props = arr.get(1)?.as_array()?;
    for prop in props {
        let prop_arr = prop.as_array()?;
        if prop_arr.first()?.as_str()? == "fn" {
            return prop_arr
                .get(3)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
    }
    None
}
