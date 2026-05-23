// tests/triage_live.rs
//
// Live integration tests for the triage engine.
//
// These tests hit real external APIs (Shodan InternetDB, ipinfo.io, RDAP)
// and are decorated #[ignore] — they do not run in CI.  Run manually:
//
//   cargo test --test triage_live -- --ignored --nocapture
//
// Targets can be overridden via environment:
//
//   APIHUNTER_TRIAGE_TARGETS="8.8.8.8,1.1.1.1" \
//     cargo test --test triage_live -- --ignored --nocapture
//
//   APIHUNTER_TRIAGE_TARGET_FILE=targets/my-list.txt \
//     cargo test --test triage_live -- --ignored --nocapture
//
// No network calls are made unless the test is explicitly invoked with --ignored.

use std::{fs, path::Path, time::Duration};

use api_scanner::triage::{
    run_triage,
    types::TriageConfig,
    TriageError,
};

// ── Default targets ───────────────────────────────────────────────────────────
//
// These are stable, well-known public IPs with predictable InternetDB records:
//
//   8.8.8.8   — Google Public DNS.  Port 53 always open.  No CVEs typically.
//               Has_likely_vulnerability = true (port 53 is high-risk).
//   1.1.1.1   — Cloudflare DNS.  Port 53 always open.  Anycast/hosting ASN.
//   45.33.32.156 — scanme.nmap.org.  Intentionally open to scanning.
//                  Port 22 (SSH) and 80 reliably open.
//
// If InternetDB hasn't indexed a target yet (new IP, low exposure) it returns
// an empty record — the test handles that gracefully.

const DEFAULT_TARGETS: &[&str] = &[
    "8.8.8.8",
    "1.1.1.1",
    "45.33.32.156", // scanme.nmap.org — explicitly open to scanning
];

const ENV_TARGETS_CSV: &str = "APIHUNTER_TRIAGE_TARGETS";
const ENV_TARGET_FILE: &str = "APIHUNTER_TRIAGE_TARGET_FILE";
const MAX_TARGETS: usize = 20;

// ── helpers ───────────────────────────────────────────────────────────────────

fn load_targets() -> Vec<String> {
    if let Ok(csv) = std::env::var(ENV_TARGETS_CSV) {
        let parsed: Vec<_> = csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .take(MAX_TARGETS)
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }

    if let Ok(path_str) = std::env::var(ENV_TARGET_FILE) {
        let path = Path::new(&path_str);
        let body = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let parsed: Vec<_> = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(ToString::to_string)
            .take(MAX_TARGETS)
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }

    DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect()
}

fn triage_config() -> TriageConfig {
    TriageConfig {
        concurrency: 10,
        timeout: Duration::from_secs(8),
        min_score: 0,
        top_n: 0,
    }
}

// ── live tests ────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "hits real internet (InternetDB, ipinfo.io, RDAP) — run manually"]
async fn triage_live_returns_entries_for_known_ips() {
    let targets = load_targets();
    println!("triage_live: probing {} targets", targets.len());

    let result = run_triage(targets.clone(), triage_config())
        .await
        .expect("run_triage must not fail at engine level");

    // Print a summary so --nocapture output is useful.
    println!(
        "elapsed={}ms total={} errors={}",
        result.elapsed_ms, result.total, result.errors.len()
    );
    for entry in &result.entries {
        println!(
            "  {} ip={:?} score={} raw={} severity={} vuln={} ports={:?} cves={:?} signals={:?}",
            entry.target,
            entry.resolved_ip,
            entry.score,
            entry.raw_score,
            entry.severity,
            entry.has_likely_vulnerability,
            entry.ports,
            entry.cve_ids,
            entry.signals,
        );
    }
    for err in &result.errors {
        println!("  ERROR: {err}");
    }

    // Basic structural assertions — not dependent on exact probe responses.
    assert_eq!(
        result.entries.len(),
        targets.len(),
        "expected one entry per target regardless of probe outcome"
    );
    assert_eq!(result.total, result.entries.len());

    // Entries must be sorted by raw_score descending.
    for window in result.entries.windows(2) {
        assert!(
            window[0].raw_score >= window[1].raw_score,
            "entries must be sorted by raw_score descending: {} ({}) before {} ({})",
            window[0].target, window[0].raw_score,
            window[1].target, window[1].raw_score,
        );
    }
}

#[tokio::test]
#[ignore = "hits real internet — run manually"]
async fn triage_live_google_dns_has_port_53_open() {
    // 8.8.8.8 is one of the most reliably indexed IPs in Shodan.
    // Port 53 should always be present in its InternetDB record.
    // If InternetDB is down or the record is empty, the test is skipped
    // rather than failed — we don't want probe outages to fail the suite.
    let result = run_triage(
        vec!["8.8.8.8".to_string()],
        triage_config(),
    )
    .await
    .expect("engine must not fail");

    assert_eq!(result.entries.len(), 1);
    let entry = &result.entries[0];

    println!(
        "8.8.8.8: score={} raw={} ports={:?} signals={:?}",
        entry.score, entry.raw_score, entry.ports, entry.signals
    );

    if entry.ports.is_empty() {
        // InternetDB returned an empty record — probe was reachable but IP not indexed.
        // This is not a failure; skip the port assertion.
        println!("SKIP: InternetDB returned no ports for 8.8.8.8 (not indexed or probe failed)");
        return;
    }

    assert!(
        entry.ports.contains(&53),
        "8.8.8.8 should have port 53 open in InternetDB, got ports: {:?}",
        entry.ports
    );
    assert!(
        entry.has_likely_vulnerability,
        "port 53 is high-risk and should set has_likely_vulnerability"
    );
}

#[tokio::test]
#[ignore = "hits real internet — run manually"]
async fn triage_live_cloudflare_has_asn_signal() {
    // 1.1.1.1 is Cloudflare — ipinfo.io always returns an AS13335 org entry.
    let result = run_triage(
        vec!["1.1.1.1".to_string()],
        triage_config(),
    )
    .await
    .expect("engine must not fail");

    assert_eq!(result.entries.len(), 1);
    let entry = &result.entries[0];

    println!(
        "1.1.1.1: asn={:?} country={:?} raw={} signals={:?}",
        entry.asn, entry.country, entry.raw_score, entry.signals
    );

    if entry.asn.is_none() {
        println!("SKIP: ipinfo.io returned no ASN for 1.1.1.1 (probe failed or rate-limited)");
        return;
    }

    assert_eq!(
        entry.asn.as_deref(),
        Some("AS13335"),
        "1.1.1.1 should be AS13335 (Cloudflare)"
    );
}

#[tokio::test]
#[ignore = "hits real internet — run manually"]
async fn triage_live_engine_errors_are_never_silent() {
    // Probe a mix of valid IPs and unresolvable garbage.
    // Every target must produce an entry — errors must appear as signals,
    // not cause entries to disappear silently.
    let targets = vec![
        "8.8.8.8".to_string(),
        "not-a-real-domain-xyzxyzxyz.invalid".to_string(),
        "1.1.1.1".to_string(),
    ];

    let result = run_triage(targets.clone(), triage_config())
        .await
        .expect("engine must not fail");

    assert_eq!(
        result.entries.len(),
        targets.len(),
        "every target — including unresolvable ones — must produce an entry"
    );

    // The unresolvable domain entry should have zero score and a resolution signal.
    let bad = result
        .entries
        .iter()
        .find(|e| e.target.contains("xyzxyzxyz"))
        .expect("unresolvable target must have an entry");

    println!(
        "unresolvable target: score={} signals={:?}",
        bad.score, bad.signals
    );

    // Score must be 0 — no probes fired, no points.
    assert_eq!(bad.score, 0);
    assert_eq!(bad.raw_score, 0);

    // has_likely_vulnerability must be false — no signals fired.
    assert!(!bad.has_likely_vulnerability);
}

#[tokio::test]
#[ignore = "hits real internet — run manually"]
async fn triage_live_result_is_complete_not_partial() {
    // run_triage must return Ok even when every probe fails (network down,
    // all timeouts).  Engine-level Err is only for structural failures.
    // This test uses a very short timeout to force probe timeouts.
    let config = TriageConfig {
        concurrency: 5,
        timeout: Duration::from_millis(1), // guaranteed timeout for every probe
        min_score: 0,
        top_n: 0,
    };

    let targets: Vec<String> = DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect();
    let n = targets.len();

    let result = run_triage(targets, config)
        .await
        .expect("engine must return Ok even when all probes time out");

    assert_eq!(
        result.entries.len(),
        n,
        "every target must produce an entry even when all probes time out"
    );

    for entry in &result.entries {
        // All probes timed out — score must be 0.
        assert_eq!(entry.score, 0, "{} should score 0 on all-timeout", entry.target);
        assert_eq!(entry.raw_score, 0);
        assert!(!entry.has_likely_vulnerability);
        // At least one timeout signal should appear.
        assert!(
            entry.signals.iter().any(|s| s.contains("timeout")),
            "{} should have a timeout signal, got: {:?}",
            entry.target, entry.signals
        );
    }
}
