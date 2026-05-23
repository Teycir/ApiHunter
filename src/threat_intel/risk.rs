// src/threat_intel/risk.rs
//
// Additive risk scorer for the threat-intel engine.
//
// Design: no hardcoded ceiling
// ─────────────────────────────
// Each scoring category declares its own weights. The model's theoretical
// maximum is derived from those weights — there is no magic number like "100"
// anywhere. Raw scores are u16 so they never overflow.
//
// Normalisation (0–100 display score) is done by dividing by MODEL_MAX.
// Severity bands operate on the normalised score.

use crate::threat_intel::types::{InternetDbData, IpInfoData, RdapDomainData, ThreatSeverity};
use serde::Serialize;

// ── High-risk ports ───────────────────────────────────────────────────────────

const HIGH_RISK_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 135, 139, 445, 1433, 1723, 3306, 3389, 4444, 4899,
    5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
];

fn is_high_risk(port: u16) -> bool {
    HIGH_RISK_PORTS.contains(&port)
}

// ── Scoring weights ───────────────────────────────────────────────────────────

const PTS_HIGH_RISK_PORT: u16 = 4;
const PTS_LOW_RISK_PORT: u16 = 1;
const PTS_CVE_UNSCORED: u16 = 2;
const PTS_HOSTING_ASN: u16 = 3;
const PTS_HONEYPOT: u16 = 5;
const PTS_SCANNER: u16 = 3;
const PTS_DOMAIN_NEW: u16 = 15;
const PTS_DOMAIN_EXPIRED: u16 = 10;
const PTS_DOMAIN_PRIVACY: u16 = 5;
const PTS_DOMAIN_NO_NS: u16 = 8;

const MAX_PORTS: u16 = PTS_HIGH_RISK_PORT * 10 + PTS_LOW_RISK_PORT * 10;
const MAX_CVES: u16 = PTS_CVE_UNSCORED * 20;
const MAX_NET: u16 = PTS_HOSTING_ASN + PTS_HONEYPOT + PTS_SCANNER;
const MAX_DOMAIN: u16 = PTS_DOMAIN_NEW + PTS_DOMAIN_EXPIRED + PTS_DOMAIN_PRIVACY + PTS_DOMAIN_NO_NS;

/// Total theoretical maximum — used as the normalisation denominator.
pub const MODEL_MAX: u16 = MAX_PORTS + MAX_CVES + MAX_NET + MAX_DOMAIN;

// ── Score breakdown ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct RiskBreakdown {
    pub ports: u16,
    pub cves: u16,
    pub network_flags: u16,
    pub domain_registration: u16,
    pub raw_total: u16,
    pub normalised: u8,
    pub model_max: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskScore {
    pub score: u8,
    pub raw_score: u16,
    pub severity: ThreatSeverity,
    pub breakdown: RiskBreakdown,
    pub signals: Vec<String>,
    pub has_likely_vulnerability: bool,
}

// ── CVSS helper ───────────────────────────────────────────────────────────────

pub fn score_cve_with_cvss(cvss: f32) -> u16 {
    if cvss >= 9.0 { 15 }
    else if cvss >= 7.0 { 8 }
    else if cvss >= 4.0 { 4 }
    else { 1 }
}

// ── Main scorer ───────────────────────────────────────────────────────────────

pub fn compute_risk_score(
    idb: Option<&InternetDbData>,
    ipinfo: Option<&IpInfoData>,
    rdap: Option<&RdapDomainData>,
) -> RiskScore {
    let mut signals: Vec<String> = Vec::new();
    let mut has_likely_vuln = false;

    let mut port_pts: u16 = 0;
    if let Some(data) = idb {
        for &p in &data.ports {
            if is_high_risk(p) {
                port_pts += PTS_HIGH_RISK_PORT;
                signals.push(format!("port {p} open (high-risk)"));
                has_likely_vuln = true;
            } else {
                port_pts += PTS_LOW_RISK_PORT;
                signals.push(format!("port {p} open"));
            }
        }
    }

    let mut cve_pts: u16 = 0;
    if let Some(data) = idb {
        for id in &data.vulns {
            cve_pts += PTS_CVE_UNSCORED;
            signals.push(format!("{id} (unscored)"));
            has_likely_vuln = true;
        }
    }

    let mut net_pts: u16 = 0;
    if let Some(info) = ipinfo {
        if info.is_hosting() {
            net_pts += PTS_HOSTING_ASN;
            signals.push("hosting/anycast ASN".to_string());
        }
    }
    if let Some(data) = idb {
        let tags: Vec<_> = data.tags.iter().map(|t| t.to_lowercase()).collect();
        if tags.iter().any(|t| t == "honeypot") {
            net_pts += PTS_HONEYPOT;
            signals.push("honeypot tag".to_string());
            has_likely_vuln = true;
        }
        if tags.iter().any(|t| t == "scanner") {
            net_pts += PTS_SCANNER;
            signals.push("scanner tag".to_string());
            has_likely_vuln = true;
        }
    }

    let mut dom_pts: u16 = 0;
    if let Some(rdap_data) = rdap {
        if let Some(age) = rdap_data.age_days() {
            if age < 30 {
                dom_pts += PTS_DOMAIN_NEW;
                signals.push(format!("domain {age} days old (newly registered)"));
            }
        }
        if rdap_data.is_expired() {
            dom_pts += PTS_DOMAIN_EXPIRED;
            signals.push("domain expired".to_string());
        }
        if rdap_data.privacy_protected {
            dom_pts += PTS_DOMAIN_PRIVACY;
            signals.push("privacy-protected registrant".to_string());
        }
        if rdap_data.nameservers.is_empty() {
            dom_pts += PTS_DOMAIN_NO_NS;
            signals.push("no nameservers".to_string());
        }
    }

    let raw_total = port_pts + cve_pts + net_pts + dom_pts;
    let normalised: u8 = if MODEL_MAX == 0 {
        0
    } else {
        ((raw_total as u32 * 100) / MODEL_MAX as u32).min(100) as u8
    };

    RiskScore {
        score: normalised,
        raw_score: raw_total,
        severity: ThreatSeverity::from_score(normalised),
        breakdown: RiskBreakdown {
            ports: port_pts,
            cves: cve_pts,
            network_flags: net_pts,
            domain_registration: dom_pts,
            raw_total,
            normalised,
            model_max: MODEL_MAX,
        },
        signals,
        has_likely_vulnerability: has_likely_vuln,
    }
}
