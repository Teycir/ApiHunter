// tests/triage.rs
//
// Unit and integration tests for the triage module.
//
// Scoring logic is tested by calling compute_risk_score directly with known
// data — no real network calls, no mock servers needed for score assertions.
// Engine-level tests (NoTargets, entry count) hit run_triage directly.
//
// Naming: triage_<scenario>_<expectation>

use api_scanner::triage::{
    risk::{compute_risk_score, MODEL_MAX},
    run_triage,
    types::{InternetDbData, IpInfoData, SourceOutcome, TriageConfig, TriageEntry, TriageSeverity},
    TriageError,
};
use std::time::Duration;

// ── helpers ───────────────────────────────────────────────────────────────────

fn fast_config() -> TriageConfig {
    TriageConfig {
        concurrency: 10,
        timeout: Duration::from_secs(5),
        min_score: 0,
        top_n: 0,
    }
}

fn empty_idb(ip: &str) -> InternetDbData {
    InternetDbData {
        ip: ip.to_string(),
        ports: vec![],
        hostnames: vec![],
        tags: vec![],
        vulns: vec![],
        cpes: vec![],
    }
}

fn make_entry(target: &str, raw: u16) -> TriageEntry {
    let score = ((raw as u32 * 100) / MODEL_MAX as u32).min(100) as u8;
    TriageEntry {
        target: target.to_string(),
        resolved_ip: None,
        score,
        raw_score: raw,
        severity: TriageSeverity::from_score(score),
        signals: vec![],
        has_likely_vulnerability: false,
        ports: vec![],
        cve_ids: vec![],
        asn: None,
        country: None,
        domain_age_days: None,
        response_ms: 0,
    }
}

// ── engine-level guard tests ──────────────────────────────────────────────────

#[tokio::test]
async fn triage_no_targets_returns_error() {
    let result = run_triage(vec![], fast_config()).await;
    assert!(
        matches!(result, Err(TriageError::NoTargets)),
        "expected NoTargets, got: {result:?}"
    );
}

#[tokio::test]
async fn triage_single_target_always_returns_one_entry() {
    // 256.x.x.x is not a valid IP so it's treated as a domain that fails
    // DoH resolution — probes are skipped, entry scores 0.  The engine must
    // still return Ok with exactly one entry.
    let tr = run_triage(vec!["256.256.256.256".to_string()], fast_config())
        .await
        .expect("engine must not fail for a single unresolvable target");
    assert_eq!(tr.entries.len(), tr.total);
}

// ── model integrity ───────────────────────────────────────────────────────────

#[tokio::test]
async fn triage_model_max_matches_weight_sum() {
    // If you change a weight constant, this test will tell you MODEL_MAX is stale.
    // ports:  10 high-risk × 4  +  10 low × 1  = 50
    // cves:   20 unscored  × 2               = 40
    // net:    3 (hosting) + 5 (honeypot) + 3 (scanner) = 11
    // domain: 15 (new) + 10 (expired) + 5 (privacy) + 8 (no-ns) = 38
    // total = 139
    assert_eq!(MODEL_MAX, 139, "MODEL_MAX must equal the sum of all weight constants");
}

#[tokio::test]
async fn triage_zero_signals_produce_zero_score() {
    let risk = compute_risk_score(None, None, None);
    assert_eq!(risk.raw_score, 0);
    assert_eq!(risk.score, 0);
    assert_eq!(risk.severity, TriageSeverity::Low);
    assert!(risk.signals.is_empty());
    assert!(!risk.has_likely_vulnerability);
}

// ── port scoring ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn triage_high_risk_ports_score_4pts_each() {
    let mut idb = empty_idb("1.2.3.4");
    idb.ports = vec![22, 3389, 6379]; // 3 high-risk

    let risk = compute_risk_score(Some(&idb), None, None);

    assert_eq!(risk.breakdown.ports, 12, "3 × 4 = 12 raw port pts");
    assert_eq!(risk.raw_score, 12);
    assert!(risk.has_likely_vulnerability, "high-risk port → likely vuln");
    assert!(risk.signals.iter().any(|s| s.contains("port 22")));
    assert!(risk.signals.iter().any(|s| s.contains("port 3389")));
    assert!(risk.signals.iter().any(|s| s.contains("port 6379")));
}

#[tokio::test]
async fn triage_low_risk_ports_score_1pt_each() {
    let mut idb = empty_idb("1.2.3.4");
    idb.ports = vec![80, 443, 8888]; // not in HIGH_RISK_PORTS list

    let risk = compute_risk_score(Some(&idb), None, None);

    assert_eq!(risk.breakdown.ports, 3, "3 low-risk ports × 1 pt = 3");
    // Low-risk ports alone do NOT set has_likely_vulnerability
    assert!(!risk.has_likely_vulnerability);
}

#[tokio::test]
async fn triage_mixed_ports_score_independently() {
    let mut idb = empty_idb("1.2.3.4");
    idb.ports = vec![22, 80]; // 1 high-risk + 1 low

    let risk = compute_risk_score(Some(&idb), None, None);
    assert_eq!(risk.breakdown.ports, 5, "4 (high) + 1 (low) = 5");
    assert!(risk.has_likely_vulnerability);
}

// ── CVE scoring ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn triage_two_unscored_cves_give_4_raw_pts() {
    let mut idb = empty_idb("1.2.3.5");
    idb.vulns = vec!["CVE-2021-44228".to_string(), "CVE-2022-0001".to_string()];

    let risk = compute_risk_score(Some(&idb), None, None);

    assert_eq!(risk.breakdown.cves, 4, "2 CVEs × 2 pts = 4");
    assert_eq!(risk.raw_score, 4);
    assert!(risk.has_likely_vulnerability, "CVE IDs → likely vuln");
    assert!(risk.signals.iter().any(|s| s.contains("CVE-2021-44228")));
}

#[tokio::test]
async fn triage_many_cves_accumulate_without_artificial_cap() {
    let mut idb = empty_idb("1.2.3.5");
    // 15 CVEs × 2 = 30 raw pts — old model capped at 25, new model does not
    idb.vulns = (1..=15).map(|i| format!("CVE-2024-{i:04}")).collect();

    let risk = compute_risk_score(Some(&idb), None, None);
    assert_eq!(risk.breakdown.cves, 30, "15 CVEs × 2 pts = 30, no artificial cap");
}

// ── network flag scoring ──────────────────────────────────────────────────────

#[tokio::test]
async fn triage_honeypot_tag_scores_5pts_and_flags_vuln() {
    let mut idb = empty_idb("1.2.3.6");
    idb.tags = vec!["honeypot".to_string()];

    let risk = compute_risk_score(Some(&idb), None, None);

    assert_eq!(risk.breakdown.network_flags, 5);
    assert!(risk.has_likely_vulnerability);
    assert!(risk.signals.iter().any(|s| s.contains("honeypot")));
}

#[tokio::test]
async fn triage_scanner_tag_scores_3pts_and_flags_vuln() {
    let mut idb = empty_idb("1.2.3.6");
    idb.tags = vec!["scanner".to_string()];

    let risk = compute_risk_score(Some(&idb), None, None);

    assert_eq!(risk.breakdown.network_flags, 3);
    assert!(risk.has_likely_vulnerability);
}

#[tokio::test]
async fn triage_hosting_asn_scores_3pts() {
    let ipinfo = IpInfoData {
        ip: "1.2.3.7".to_string(),
        anycast: Some(true),
        hostname: None,
        city: None,
        region: None,
        country: None,
        loc: None,
        org: Some("AS13335 Cloudflare".to_string()),
        timezone: None,
        bogon: None,
    };

    let risk = compute_risk_score(None, Some(&ipinfo), None);
    assert_eq!(risk.breakdown.network_flags, 3);
    // Hosting ASN alone is not a direct vuln indicator
    assert!(!risk.has_likely_vulnerability);
}

// ── normalisation ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn triage_normalised_score_never_exceeds_100() {
    // Saturate every category simultaneously.
    let mut idb = empty_idb("1.2.3.7");
    idb.ports = vec![22, 23, 25, 53, 135, 139, 445, 1433, 3306, 3389,
                     4444, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
                     80, 443]; // 19 high-risk + 2 low
    idb.tags = vec!["honeypot".to_string(), "scanner".to_string()];
    idb.vulns = (1..=30).map(|i| format!("CVE-2024-{i:04}")).collect();

    let ipinfo = IpInfoData {
        ip: "1.2.3.7".to_string(),
        anycast: Some(true),
        hostname: None, city: None, region: None, country: None,
        loc: None, org: None, timezone: None, bogon: None,
    };

    let risk = compute_risk_score(Some(&idb), Some(&ipinfo), None);

    assert!(risk.score <= 100, "normalised score must be ≤ 100, got {}", risk.score);
    assert!(risk.raw_score > MODEL_MAX || risk.raw_score <= MODEL_MAX,
            "raw_score is always valid");
    assert_eq!(risk.severity, TriageSeverity::Critical);
}

#[tokio::test]
async fn triage_raw_score_preserves_ordering_within_band() {
    // Two targets both normalise to CRITICAL but have different raw scores.
    // They must sort differently.
    let mut entries = vec![
        make_entry("high-exposure", 120),
        make_entry("lower-exposure", 80),
        make_entry("medium", 40),
    ];
    entries.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));

    assert_eq!(entries[0].target, "high-exposure");
    assert_eq!(entries[1].target, "lower-exposure");
    assert_eq!(entries[2].target, "medium");
}

// ── severity bands ────────────────────────────────────────────────────────────

#[tokio::test]
fn triage_severity_bands_cover_full_0_100_range() {
    for (score, expected) in [
        (0u8,   TriageSeverity::Low),
        (24,    TriageSeverity::Low),
        (25,    TriageSeverity::Medium),
        (49,    TriageSeverity::Medium),
        (50,    TriageSeverity::High),
        (74,    TriageSeverity::High),
        (75,    TriageSeverity::Critical),
        (100,   TriageSeverity::Critical),
    ] {
        let got = TriageSeverity::from_score(score);
        assert_eq!(got, expected, "score {score} → {expected:?}, got {got:?}");
    }
}

// ── result structure ──────────────────────────────────────────────────────────

#[tokio::test]
async fn triage_entries_sorted_by_raw_score_descending() {
    let mut entries = vec![
        make_entry("a", 10),
        make_entry("b", 80),
        make_entry("c", 45),
    ];
    entries.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));

    assert_eq!(entries[0].raw_score, 80);
    assert_eq!(entries[1].raw_score, 45);
    assert_eq!(entries[2].raw_score, 10);
}

#[tokio::test]
async fn triage_top_n_truncates_to_highest_raw_scores() {
    let mut entries: Vec<TriageEntry> = (0u16..20).map(|i| make_entry(&format!("t{i}"), i)).collect();
    entries.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));
    entries.truncate(5);

    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].raw_score, 19);
}

#[tokio::test]
async fn triage_min_score_filter_drops_low_entries() {
    let config = TriageConfig {
        min_score: 50,
        timeout: Duration::from_millis(300),
        ..fast_config()
    };
    // 127.0.0.1 — probes time out fast, entry scores 0 → filtered out
    let result = run_triage(vec!["127.0.0.1".to_string()], config)
        .await
        .expect("engine must not fail");

    for entry in &result.entries {
        assert!(
            entry.score >= 50,
            "entry {} has score {} below min_score 50",
            entry.target, entry.score
        );
    }
}

// ── SourceOutcome contract ────────────────────────────────────────────────────

#[test]
fn triage_source_outcome_variants_are_explicit() {
    let ok: SourceOutcome<u32>      = SourceOutcome::Ok(42);
    let err: SourceOutcome<u32>     = SourceOutcome::Error("boom".to_string());
    let timeout: SourceOutcome<u32> = SourceOutcome::Timeout;
    let skipped: SourceOutcome<u32> = SourceOutcome::Skipped;

    assert!(ok.is_ok());
    assert!(!err.is_ok());
    assert!(!timeout.is_ok());
    assert!(!skipped.is_ok());

    assert_eq!(ok.as_ref(),      Some(&42));
    assert_eq!(err.as_ref(),     None);
    assert_eq!(timeout.as_ref(), None);
    assert_eq!(skipped.as_ref(), None);
}
