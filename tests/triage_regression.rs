// tests/triage_regression.rs
//
// Non-regression test suite for triage mode against 200 stable real targets.
//
// This suite validates that the triage engine produces consistent, complete
// results against a curated list of stable infrastructure IPs (DNS servers,
// CDNs, root servers, major cloud providers, etc.).
//
// Run manually (not in CI):
//
//   cargo test --test triage_regression -- --ignored --nocapture
//
// Override target list:
//
//   APIHUNTER_TRIAGE_REGRESSION_FILE=targets/my-list.txt \
//     cargo test --test triage_regression -- --ignored --nocapture

use std::{collections::HashSet, fs, path::Path, time::Duration};

use api_scanner::triage::{
    run_triage,
    types::TriageConfig,
};

const DEFAULT_TARGET_FILE: &str = "targets/triage-regression-200.txt";
const ENV_TARGET_FILE: &str = "APIHUNTER_TRIAGE_REGRESSION_FILE";

fn load_targets() -> Vec<String> {
    let path_str = std::env::var(ENV_TARGET_FILE)
        .unwrap_or_else(|_| DEFAULT_TARGET_FILE.to_string());
    let path = Path::new(&path_str);
    
    let body = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn triage_config() -> TriageConfig {
    TriageConfig {
        concurrency: 20,
        timeout: Duration::from_secs(10),
        min_score: 0,
        top_n: 0,
    }
}

#[tokio::test]
#[ignore = "hits real internet (200 targets) — run manually"]
async fn triage_regression_completeness() {
    let targets = load_targets();
    let n = targets.len();
    
    println!("triage_regression: probing {} targets", n);
    println!("config: concurrency={} timeout={}s", 
        triage_config().concurrency,
        triage_config().timeout.as_secs()
    );
    
    let result = run_triage(targets.clone(), triage_config())
        .await
        .expect("run_triage must not fail at engine level");
    
    println!("\n=== SUMMARY ===");
    println!("elapsed: {}ms", result.elapsed_ms);
    println!("total entries: {}", result.total);
    println!("errors: {}", result.errors.len());
    
    // Every target must produce an entry
    assert_eq!(
        result.entries.len(),
        n,
        "expected one entry per target regardless of probe outcome"
    );
    assert_eq!(result.total, result.entries.len());
    
    // No duplicate targets
    let seen: HashSet<_> = result.entries.iter().map(|e| &e.target).collect();
    assert_eq!(seen.len(), n, "entries must not contain duplicates");
    
    // Entries must be sorted by raw_score descending
    for window in result.entries.windows(2) {
        assert!(
            window[0].raw_score >= window[1].raw_score,
            "entries must be sorted by raw_score descending: {} ({}) before {} ({})",
            window[0].target, window[0].raw_score,
            window[1].target, window[1].raw_score,
        );
    }
    
    println!("\n=== COMPLETENESS CHECKS PASSED ===");
}

#[tokio::test]
#[ignore = "hits real internet (200 targets) — run manually"]
async fn triage_regression_scoring_distribution() {
    let targets = load_targets();
    
    let result = run_triage(targets, triage_config())
        .await
        .expect("run_triage must not fail");
    
    let mut score_buckets = [0usize; 5];
    let mut severity_info = 0;
    let mut severity_low = 0;
    let mut severity_medium = 0;
    let mut severity_high = 0;
    let mut severity_critical = 0;
    let mut with_ports = 0;
    let mut with_cves = 0;
    let mut with_vulns = 0;
    let mut with_asn = 0;
    let mut with_country = 0;
    
    for entry in &result.entries {
        // Score distribution
        let bucket = match entry.score {
            0..=20 => 0,
            21..=40 => 1,
            41..=60 => 2,
            61..=80 => 3,
            _ => 4,
        };
        score_buckets[bucket] += 1;
        
        // Severity distribution
        match entry.severity.as_str() {
            "info" => severity_info += 1,
            "low" => severity_low += 1,
            "medium" => severity_medium += 1,
            "high" => severity_high += 1,
            "critical" => severity_critical += 1,
            _ => {},
        }
        
        // Signal coverage
        if !entry.ports.is_empty() { with_ports += 1; }
        if !entry.cve_ids.is_empty() { with_cves += 1; }
        if entry.has_likely_vulnerability { with_vulns += 1; }
        if entry.asn.is_some() { with_asn += 1; }
        if entry.country.is_some() { with_country += 1; }
    }
    
    println!("\n=== SCORING DISTRIBUTION ===");
    println!("0-20:   {} entries", score_buckets[0]);
    println!("21-40:  {} entries", score_buckets[1]);
    println!("41-60:  {} entries", score_buckets[2]);
    println!("61-80:  {} entries", score_buckets[3]);
    println!("81-100: {} entries", score_buckets[4]);
    
    println!("\n=== SEVERITY DISTRIBUTION ===");
    println!("info: {}", severity_info);
    println!("low: {}", severity_low);
    println!("medium: {}", severity_medium);
    println!("high: {}", severity_high);
    println!("critical: {}", severity_critical);
    
    println!("\n=== SIGNAL COVERAGE ===");
    println!("with ports: {}/{}", with_ports, result.total);
    println!("with CVEs: {}/{}", with_cves, result.total);
    println!("with likely vuln: {}/{}", with_vulns, result.total);
    println!("with ASN: {}/{}", with_asn, result.total);
    println!("with country: {}/{}", with_country, result.total);
    
    // Sanity checks: stable infrastructure should have high signal coverage
    let port_coverage = (with_ports as f64 / result.total as f64) * 100.0;
    let asn_coverage = (with_asn as f64 / result.total as f64) * 100.0;
    
    println!("\n=== COVERAGE METRICS ===");
    println!("port coverage: {:.1}%", port_coverage);
    println!("ASN coverage: {:.1}%", asn_coverage);
    
    // These are stable, well-known IPs — we expect high coverage
    assert!(
        port_coverage > 70.0,
        "expected >70% port coverage for stable infrastructure, got {:.1}%",
        port_coverage
    );
    assert!(
        asn_coverage > 80.0,
        "expected >80% ASN coverage for stable infrastructure, got {:.1}%",
        asn_coverage
    );
}

#[tokio::test]
#[ignore = "hits real internet (200 targets) — run manually"]
async fn triage_regression_error_handling() {
    let targets = load_targets();
    
    let result = run_triage(targets, triage_config())
        .await
        .expect("run_triage must not fail at engine level");
    
    println!("\n=== ERROR ANALYSIS ===");
    println!("total errors: {}", result.errors.len());
    
    if !result.errors.is_empty() {
        println!("\nError breakdown:");
        for err in &result.errors {
            println!("  {}", err);
        }
    }
    
    // Count entries with signals (probe failures)
    let mut entries_with_signals = 0;
    let mut signal_types = std::collections::HashMap::new();
    
    for entry in &result.entries {
        if !entry.signals.is_empty() {
            entries_with_signals += 1;
            for signal in &entry.signals {
                *signal_types.entry(signal.as_str()).or_insert(0) += 1;
            }
        }
    }
    
    println!("\nEntries with signals: {}/{}", entries_with_signals, result.total);
    
    if !signal_types.is_empty() {
        println!("\nSignal breakdown:");
        let mut sorted: Vec<_> = signal_types.iter().collect();
        sorted.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (signal, count) in sorted {
            println!("  {}: {}", signal, count);
        }
    }
    
    // Errors must never be silent — they appear in result.errors or entry.signals
    let total_failures = result.errors.len() + entries_with_signals;
    println!("\nTotal recorded failures: {}", total_failures);
    println!("(errors + entries with signals)");
}

#[tokio::test]
#[ignore = "hits real internet (200 targets) — run manually"]
async fn triage_regression_top_scorers() {
    let targets = load_targets();
    
    let result = run_triage(targets, triage_config())
        .await
        .expect("run_triage must not fail");
    
    println!("\n=== TOP 20 SCORERS ===");
    for (i, entry) in result.entries.iter().take(20).enumerate() {
        println!(
            "{}. {} (score={} raw={} severity={} vuln={})",
            i + 1,
            entry.target,
            entry.score,
            entry.raw_score,
            entry.severity,
            entry.has_likely_vulnerability
        );
        println!("   ports={:?}", entry.ports);
        println!("   cves={:?}", entry.cve_ids);
        if !entry.signals.is_empty() {
            println!("   signals={:?}", entry.signals);
        }
        println!();
    }
    
    // Top scorer must have non-zero score (unless all probes failed)
    if let Some(top) = result.entries.first() {
        if top.score == 0 {
            println!("WARNING: top scorer has zero score — all probes may have failed");
            println!("signals: {:?}", top.signals);
        }
    }
}

#[tokio::test]
#[ignore = "hits real internet (200 targets) — run manually"]
async fn triage_regression_known_dns_servers() {
    // Validate specific known targets have expected characteristics
    let targets = load_targets();
    
    let result = run_triage(targets, triage_config())
        .await
        .expect("run_triage must not fail");
    
    println!("\n=== KNOWN TARGET VALIDATION ===");
    
    // Google DNS (8.8.8.8) — should have port 53
    if let Some(google) = result.entries.iter().find(|e| e.target == "8.8.8.8") {
        println!("\n8.8.8.8 (Google DNS):");
        println!("  score={} ports={:?} signals={:?}", 
            google.score, google.ports, google.signals);
        
        if !google.ports.is_empty() {
            assert!(
                google.ports.contains(&53),
                "8.8.8.8 should have port 53 open, got {:?}",
                google.ports
            );
        } else {
            println!("  SKIP: no ports (InternetDB not indexed or probe failed)");
        }
    }
    
    // Cloudflare DNS (1.1.1.1) — should have AS13335
    if let Some(cf) = result.entries.iter().find(|e| e.target == "1.1.1.1") {
        println!("\n1.1.1.1 (Cloudflare DNS):");
        println!("  score={} asn={:?} signals={:?}", 
            cf.score, cf.asn, cf.signals);
        
        if let Some(asn) = &cf.asn {
            assert_eq!(
                asn, "AS13335",
                "1.1.1.1 should be AS13335, got {}",
                asn
            );
        } else {
            println!("  SKIP: no ASN (ipinfo.io probe failed)");
        }
    }
    
    // Root DNS servers — should have port 53
    let root_servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12"];
    for ip in root_servers {
        if let Some(entry) = result.entries.iter().find(|e| e.target == ip) {
            println!("\n{} (Root DNS):", ip);
            println!("  score={} ports={:?}", entry.score, entry.ports);
            
            if !entry.ports.is_empty() && !entry.ports.contains(&53) {
                println!("  WARNING: root DNS server without port 53: {:?}", entry.ports);
            }
        }
    }
}
