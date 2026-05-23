//! Post-scan enrichment.
//!
//! Takes a scan-findings NDJSON stream, extracts unique target hosts,
//! runs lightweight threat-intel probes via the triage engine, and
//! produces enriched NDJSON where every finding gains a `threat_intel`
//! block: open ports, CVE IDs, ASN, country, domain age.
//!
//! # Architecture note
//!
//! Enrichment is a *post-scan* step — it is intentionally separate from
//! the scanner pipeline. The triage probes add **depth** (threat context),
//! not **speed**. Running them before or during a mass scan increases
//! latency per target; running them after means the fast sweep finishes
//! first and only the confirmed-vulnerable hosts pay the probe cost.
//!
//! Pipeline:
//! ```text
//! 5 000 targets
//!   │
//!   ▼  apihunter --preset mass --urls all.txt --output findings.ndjson
//!   │  (fast passive sweep, high concurrency, no discovery)
//!   ▼
//! findings.ndjson   (only hosts with ≥ 1 finding)
//!   │
//!   ▼  apihunter enrich --findings findings.ndjson --output enriched.ndjson
//!   │  (one InternetDB+ipinfo+RDAP probe per unique host)
//!   ▼
//! enriched.ndjson   (findings + ports/CVEs/ASN/domain-age context)
//!   │
//!   ▼  apihunter --preset deep --urls hot-targets.txt --active-checks
//! ```
//!
//! One triage probe per *unique host* regardless of how many findings
//! came from that host — probes are never duplicated.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::triage::{
    run_triage,
    types::{TriageConfig, TriageEntry},
};

// ── Input ─────────────────────────────────────────────────────────────────────

/// Minimal NDJSON finding shape — tolerant of extra fields via flatten.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawFinding {
    pub url: String,
    pub check: String,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub scanner: Option<String>,
}

// ── Output ────────────────────────────────────────────────────────────────────

/// Original finding + threat-intel overlay.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichedFinding {
    /// All original finding fields pass through unchanged.
    #[serde(flatten)]
    pub finding: RawFinding,
    /// Threat-intel from triage probes. None when the host could not be
    /// resolved or all probes timed out / errored.
    pub threat_intel: Option<TriageEntry>,
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Caller-supplied options for the enrichment engine.
#[derive(Debug, Clone)]
pub struct EnrichConfig {
    /// Parallel probe tasks (one probe = one unique host).
    pub concurrency: usize,
    /// Per-probe timeout. 5 s is sufficient for InternetDB + ipinfo.io.
    pub timeout: Duration,
}

impl Default for EnrichConfig {
    fn default() -> Self {
        Self {
            concurrency: 50,
            timeout: Duration::from_secs(5),
        }
    }
}

// ── Result ────────────────────────────────────────────────────────────────────

/// Everything produced by a completed enrichment pass.
#[derive(Debug)]
pub struct EnrichResult {
    pub enriched: Vec<EnrichedFinding>,
    /// Number of input findings (before enrichment).
    pub total_findings: usize,
    /// Number of *unique* hosts that were probed.
    pub unique_hosts: usize,
    /// Wall-clock time for the full enrichment pass.
    pub elapsed_ms: u64,
    /// Per-probe errors (non-fatal — host appears in output with
    /// `threat_intel: null`).
    pub triage_errors: Vec<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Load findings from a newline-delimited JSON file.
///
/// Blank lines and lines starting with `#` are silently skipped.
pub fn load_findings_ndjson(path: &Path) -> Result<Vec<RawFinding>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Cannot open findings file: {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut findings = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line.context("Failed to read findings file")?;
        let line = line.trim().to_owned();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: RawFinding = serde_json::from_str(&line)
            .with_context(|| format!("Invalid JSON on line {}: {line}", i + 1))?;
        findings.push(f);
    }

    Ok(findings)
}

/// Parse findings from an in-memory NDJSON string (used by the desktop app).
pub fn parse_findings_ndjson(ndjson: &str) -> Result<Vec<RawFinding>> {
    let mut findings = Vec::new();
    for (i, line) in ndjson.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: RawFinding = serde_json::from_str(line)
            .with_context(|| format!("Invalid JSON on line {}: {line}", i + 1))?;
        findings.push(f);
    }
    Ok(findings)
}

/// Enrich a batch of findings with threat-intel probes.
///
/// Fires one InternetDB + ipinfo.io + RDAP probe per unique host,
/// bounded by `config.concurrency`. Returns immediately for empty input.
pub async fn enrich_findings(
    findings: Vec<RawFinding>,
    config: EnrichConfig,
) -> Result<EnrichResult> {
    let start = Instant::now();
    let total_findings = findings.len();

    if total_findings == 0 {
        return Ok(EnrichResult {
            enriched: Vec::new(),
            total_findings: 0,
            unique_hosts: 0,
            elapsed_ms: 0,
            triage_errors: Vec::new(),
        });
    }

    // Collect unique probe targets (host[:port]) from finding URLs.
    let unique_probe_targets: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        findings
            .iter()
            .filter_map(|f| host_probe_target(&f.url))
            .filter(|h| seen.insert(h.clone()))
            .collect()
    };
    let unique_hosts = unique_probe_targets.len();

    tracing::info!(
        findings = total_findings,
        unique_hosts,
        concurrency = config.concurrency,
        "Enrichment: starting threat-intel probes"
    );

    // Run triage probes (InternetDB + ipinfo.io + RDAP).
    let triage_config = TriageConfig {
        concurrency: config.concurrency,
        timeout: config.timeout,
        min_score: 0,
        top_n: 0,
    };

    let triage_result = run_triage(unique_probe_targets, triage_config)
        .await
        .context("Triage probes failed during enrichment")?;

    tracing::info!(
        probed = triage_result.total,
        errors = triage_result.errors.len(),
        elapsed_ms = triage_result.elapsed_ms,
        "Enrichment: triage probes complete"
    );

    // Build host-probe-target → TriageEntry lookup map.
    let intel_map: HashMap<String, TriageEntry> = triage_result
        .entries
        .into_iter()
        .map(|entry| {
            let key = host_probe_target(&entry.target)
                .unwrap_or_else(|| entry.target.clone());
            (key, entry)
        })
        .collect();

    // Attach threat-intel to every finding by matching on host.
    let enriched = findings
        .into_iter()
        .map(|f| {
            let key = host_probe_target(&f.url).unwrap_or_default();
            let threat_intel = intel_map.get(&key).cloned();
            EnrichedFinding { finding: f, threat_intel }
        })
        .collect();

    Ok(EnrichResult {
        enriched,
        total_findings,
        unique_hosts,
        elapsed_ms: start.elapsed().as_millis() as u64,
        triage_errors: triage_result.errors,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Return the canonical `host[:port]` probe key for a URL or bare host string.
fn host_probe_target(raw: &str) -> Option<String> {
    // Try full URL first.
    if let Ok(u) = Url::parse(raw) {
        let host = u.host_str()?.to_ascii_lowercase();
        return Some(match u.port() {
            Some(p) if !matches!((u.scheme(), p), ("https", 443) | ("http", 80)) => {
                format!("{host}:{p}")
            }
            _ => host,
        });
    }
    // Fall back: treat raw as a bare host (for triage target passthrough).
    let bare = raw
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?
        .trim();
    if bare.is_empty() { None } else { Some(bare.to_ascii_lowercase()) }
}
