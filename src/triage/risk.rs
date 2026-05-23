// src/triage/risk.rs
//
// Additive risk scorer.
//
// Design: no hardcoded ceiling
// ─────────────────────────────
// Each scoring category declares its own weights.  The model's theoretical
// maximum is derived at compile time from those weights — there is no magic
// number like "100" anywhere.  Raw scores are u16 so they never overflow even
// if new categories are added.
//
// Normalisation (0–100 display score) is done by dividing by
// ScoringModel::MAX, which is always recomputed from the actual weights.
// Severity bands operate on the normalised score so they stay meaningful as
// the model evolves.
//
// "Likely vulnerability" surface
// ───────────────────────────────
// A target is considered to have likely vulnerabilities when it has ANY of:
//   • at least one high-risk port open
//   • at least one CVE ID listed
//   • a honeypot or scanner tag (indicating active attacker interest)
//
// This predicate is exposed as RiskScore::has_likely_vulnerability so callers
// can filter without re-implementing the logic.

use crate::triage::types::{InternetDbData, IpInfoData, RdapDomainData, TriageSeverity};
use serde::Serialize;

// ── High-risk ports ───────────────────────────────────────────────────────────

const HIGH_RISK_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP open relay
    53,    // DNS open resolver
    135,   // RPC
    139,   // NetBIOS
    445,   // SMB (EternalBlue)
    1433,  // MSSQL
    1723,  // PPTP VPN
    3306,  // MySQL
    3389,  // RDP
    4444,  // Metasploit default / Feodo C2
    4899,  // Radmin
    5432,  // PostgreSQL
    5900,  // VNC
    6379,  // Redis (no-auth default)
    8080,  // Alt HTTP / admin panels
    8443,  // Alt HTTPS
    9200,  // Elasticsearch (no-auth default)
    11211, // Memcached
    27017, // MongoDB (no-auth default)
];

fn is_high_risk(port: u16) -> bool {
    HIGH_RISK_PORTS.contains(&port)
}

// ── Scoring model — weights live here, nowhere else ──────────────────────────

/// Points awarded per high-risk port (uncapped within the category).
const PTS_HIGH_RISK_PORT: u16 = 4;
/// Points awarded per ordinary open port.
const PTS_LOW_RISK_PORT: u16 = 1;

/// Points per CVE ID when no CVSS is available (triage-speed default).
const PTS_CVE_UNSCORED: u16 = 2;

/// Network flag weights.
const PTS_HOSTING_ASN: u16 = 3;
const PTS_HONEYPOT: u16 = 5;
const PTS_SCANNER: u16 = 3;

/// Domain registration weights.
const PTS_DOMAIN_NEW: u16 = 15;    // < 30 days old
const PTS_DOMAIN_EXPIRED: u16 = 10;
const PTS_DOMAIN_PRIVACY: u16 = 5;
const PTS_DOMAIN_NO_NS: u16 = 8;

/// Theoretical maximum of each category, derived from the weights above.
/// These are used for normalisation — never for capping.
///
/// Ports: assume a target could realistically expose all HIGH_RISK_PORTS (22
/// of them) plus a handful of ordinary ports.  We bound the realistic maximum
/// at 10 high-risk + 10 ordinary so the category doesn't dominate absurdly.
const MAX_PORTS: u16 = PTS_HIGH_RISK_PORT * 10 + PTS_LOW_RISK_PORT * 10;

/// CVEs: InternetDB lists up to ~20 CVEs for the most exposed hosts.
const MAX_CVES: u16 = PTS_CVE_UNSCORED * 20;

/// Network flags: all three fire simultaneously.
const MAX_NET: u16 = PTS_HOSTING_ASN + PTS_HONEYPOT + PTS_SCANNER;

/// Domain: all four conditions fire simultaneously.
const MAX_DOMAIN: u16 = PTS_DOMAIN_NEW + PTS_DOMAIN_EXPIRED + PTS_DOMAIN_PRIVACY + PTS_DOMAIN_NO_NS;

/// Total theoretical maximum — used as the normalisation denominator.
pub const MODEL_MAX: u16 = MAX_PORTS + MAX_CVES + MAX_NET + MAX_DOMAIN;

// ── Score breakdown ───────────────────────────────────────────────────────────

/// Raw (unnormalised) per-category point totals.
#[derive(Debug, Clone, Serialize)]
pub struct RiskBreakdown {
    /// Raw points from open ports.
    pub ports: u16,
    /// Raw points from CVE exposure.
    pub cves: u16,
    /// Raw points from network flags (honeypot, scanner, hosting ASN).
    pub network_flags: u16,
    /// Raw points from domain registration signals.
    pub domain_registration: u16,
    /// Sum of all categories (raw, not normalised).
    pub raw_total: u16,
    /// 0–100 normalised score (raw_total / MODEL_MAX × 100).
    pub normalised: u8,
    /// The model maximum used for normalisation — always MODEL_MAX.
    /// Included in the output so downstream consumers can verify/reproduce.
    pub model_max: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskScore {
    /// 0–100 normalised score — use for display and severity bands.
    pub score: u8,
    /// Raw unnormalised total — use for sort ordering within a severity band.
    pub raw_score: u16,
    pub severity: TriageSeverity,
    pub breakdown: RiskBreakdown,
    /// Human-readable signals explaining the score.
    pub signals: Vec<String>,
    /// True when the target has at least one indicator of likely vulnerability.
    /// Independent of score — a target can have a low normalised score but
    /// still warrant promotion if it carries a CVE or a C2 port.
    pub has_likely_vulnerability: bool,
}

// ── CVSS helpers ──────────────────────────────────────────────────────────────

/// Score a single CVE when the caller already has CVSS data.
/// Use this for Layer-3 (post-promotion) enrichment, not triage speed.
pub fn score_cve_with_cvss(cvss: f32) -> u16 {
    if cvss >= 9.0 { 15 }
    else if cvss >= 7.0 { 8 }
    else if cvss >= 4.0 { 4 }
    else { 1 }
}

// ── Main scorer ───────────────────────────────────────────────────────────────

/// Compute a risk score from three optional probe results.
/// All arguments are optional — any missing source contributes 0 pts.
pub fn compute_risk_score(
    idb: Option<&InternetDbData>,
    ipinfo: Option<&IpInfoData>,
    rdap: Option<&RdapDomainData>,
) -> RiskScore {
    let mut signals: Vec<String> = Vec::new();
    let mut has_likely_vuln = false;

    // ── Ports ─────────────────────────────────────────────────────────────────
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

    // ── CVEs ──────────────────────────────────────────────────────────────────
    let mut cve_pts: u16 = 0;
    if let Some(data) = idb {
        for id in &data.vulns {
            cve_pts += PTS_CVE_UNSCORED;
            signals.push(format!("{id} (unscored)"));
            has_likely_vuln = true;
        }
    }

    // ── Network flags ─────────────────────────────────────────────────────────
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

    // ── Domain registration ───────────────────────────────────────────────────
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

    // ── Totals and normalisation ───────────────────────────────────────────────
    let raw_total = port_pts + cve_pts + net_pts + dom_pts;

    // Normalise to 0–100 using the model's own theoretical maximum.
    // If somehow raw_total exceeds MODEL_MAX (e.g. a target exposes every
    // high-risk port ever defined), we clamp to 100 rather than panic — but
    // the raw_score is always preserved unclamped for sort ordering.
    let normalised: u8 = if MODEL_MAX == 0 {
        0
    } else {
        ((raw_total as u32 * 100) / MODEL_MAX as u32).min(100) as u8
    };

    RiskScore {
        score: normalised,
        raw_score: raw_total,
        severity: TriageSeverity::from_score(normalised),
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
