// src/threat_intel/types.rs
//
// Shared data types for the threat-intel module.
// No dependencies on the scanner pipeline — these are self-contained.

use serde::{Deserialize, Serialize};

// ── Severity ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
    pub fn from_score(score: u8) -> Self {
        match score {
            75..=100 => Self::Critical,
            50..=74 => Self::High,
            25..=49 => Self::Medium,
            _ => Self::Low,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Source results ────────────────────────────────────────────────────────────

/// Raw response from Shodan InternetDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetDbData {
    pub ip: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub vulns: Vec<String>,
    #[serde(default)]
    pub cpes: Vec<String>,
}

/// Raw response from ipinfo.io.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInfoData {
    pub ip: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub loc: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub anycast: Option<bool>,
    #[serde(default)]
    pub bogon: Option<bool>,
}

impl IpInfoData {
    pub fn asn(&self) -> Option<String> {
        self.org.as_deref().and_then(|o| {
            let part = o.split_whitespace().next()?;
            if part.starts_with("AS") {
                Some(part.to_string())
            } else {
                None
            }
        })
    }

    pub fn isp(&self) -> Option<String> {
        self.org.as_deref().and_then(|o| {
            let mut parts = o.splitn(2, ' ');
            parts.next();
            parts.next().map(|s| s.to_string())
        })
    }

    pub fn is_hosting(&self) -> bool {
        self.anycast.unwrap_or(false)
    }
}

/// Minimal RDAP domain data (domain-only; IP RDAP skipped for speed).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RdapDomainData {
    pub domain: Option<String>,
    pub registrar: Option<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub nameservers: Vec<String>,
    pub privacy_protected: bool,
}

impl RdapDomainData {
    pub fn age_days(&self) -> Option<i64> {
        let created = self.created.as_deref()?;
        let dt = chrono::DateTime::parse_from_rfc3339(created).ok()?;
        let age = chrono::Utc::now().signed_duration_since(dt.with_timezone(&chrono::Utc));
        Some(age.num_days())
    }

    pub fn is_expired(&self) -> bool {
        self.expires.as_deref().is_some_and(|e| {
            chrono::DateTime::parse_from_rfc3339(e)
                .map(|dt| dt.with_timezone(&chrono::Utc) < chrono::Utc::now())
                .unwrap_or(false)
        })
    }
}

// ── Per-source result wrapper ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum SourceOutcome<T> {
    Ok(T),
    Timeout,
    Error(String),
    Skipped,
}

impl<T> SourceOutcome<T> {
    pub fn as_ref(&self) -> Option<&T> {
        if let Self::Ok(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}

// ── Threat-intel entry (one per target) ───────────────────────────────────────

/// Everything produced for a single probed host.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatIntelEntry {
    /// Original target string as supplied by the caller.
    pub target: String,
    /// IP that was probed (resolved from domain if needed).
    pub resolved_ip: Option<String>,
    /// Normalised display score 0–100.
    pub score: u8,
    /// Raw unnormalised point total — use for sort ordering within a band.
    pub raw_score: u16,
    /// Severity band derived from the normalised score.
    pub severity: ThreatSeverity,
    /// Human-readable signal list that explains the score.
    pub signals: Vec<String>,
    /// True when the target carries at least one direct vulnerability indicator.
    pub has_likely_vulnerability: bool,
    /// Open ports from InternetDB.
    pub ports: Vec<u16>,
    /// CVE IDs from InternetDB.
    pub cve_ids: Vec<String>,
    /// ASN string e.g. "AS15169".
    pub asn: Option<String>,
    /// Two-letter country code.
    pub country: Option<String>,
    /// Age of domain registration in days, or None for IPs / unresolvable domains.
    pub domain_age_days: Option<i64>,
    /// Wall-clock ms for all probes combined.
    pub response_ms: u64,
}

// ── Probe result set (returned from run_probes) ───────────────────────────────

#[derive(Debug, Serialize)]
pub struct ThreatIntelResult {
    /// Entries sorted by score descending.
    pub entries: Vec<ThreatIntelEntry>,
    pub total: usize,
    pub elapsed_ms: u64,
    pub errors: Vec<String>,
}

// ── Probe config ──────────────────────────────────────────────────────────────

/// Caller-supplied options — completely independent of the main Config.
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    /// Parallel probe tasks.
    pub concurrency: usize,
    /// Per-probe timeout.
    pub timeout: std::time::Duration,
    /// Emit only entries at or above this score.
    pub min_score: u8,
    /// If > 0, truncate output to the top N entries.
    pub top_n: usize,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            concurrency: 100,
            timeout: std::time::Duration::from_secs(5),
            min_score: 0,
            top_n: 0,
        }
    }
}
