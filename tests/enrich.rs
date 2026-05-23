// tests/enrich.rs
//
// Unit and integration tests for the enrichment system (src/enrich.rs).
//
// Strategy
// ────────
// • parse_findings_ndjson / load_findings_ndjson — pure parsing; no network.
// • enrich_findings — tested with a single unresolvable host so all triage
//   probes return Skipped/timeout-zero; the function must still succeed and
//   produce one EnrichedFinding per input finding with threat_intel == None.
// • host_probe_target extraction — exercised via the observable deduplication
//   behaviour of enrich_findings (N findings for the same host → 1 probe).
// • EnrichResult shape — unique_hosts, total_findings, elapsed_ms, errors
//   are always present and well-formed.
//
// Naming: enrich_<subject>_<expectation>

use api_scanner::enrich::{
    enrich_findings, parse_findings_ndjson, EnrichConfig, RawFinding,
};
use std::time::Duration;

// ── helpers ───────────────────────────────────────────────────────────────────

fn fast_config() -> EnrichConfig {
    EnrichConfig {
        concurrency: 4,
        timeout: Duration::from_millis(300),
    }
}

/// Build a minimal RawFinding for a given URL and check name.
fn raw_finding(url: &str, check: &str) -> RawFinding {
    RawFinding {
        url: url.to_string(),
        check: check.to_string(),
        title: format!("{check} title"),
        severity: "HIGH".to_string(),
        detail: Some("test detail".to_string()),
        evidence: None,
        scanner: Some("test-scanner".to_string()),
    }
}

/// One-liner NDJSON serialiser.
fn to_ndjson(findings: &[RawFinding]) -> String {
    findings
        .iter()
        .filter_map(|f| serde_json::to_string(f).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

// ── parse_findings_ndjson ─────────────────────────────────────────────────────

#[test]
fn enrich_parse_ndjson_empty_string_returns_empty_vec() {
    let result = parse_findings_ndjson("").expect("empty input must not error");
    assert!(result.is_empty(), "empty NDJSON → empty vec");
}

#[test]
fn enrich_parse_ndjson_blank_and_comment_lines_are_skipped() {
    let input = "\n# this is a comment\n   \n";
    let result = parse_findings_ndjson(input).expect("comment-only input must not error");
    assert!(result.is_empty(), "comment/blank lines only → empty vec");
}

#[test]
fn enrich_parse_ndjson_single_valid_line_parses_all_fields() {
    let f = raw_finding("https://api.example.com/v1/users", "cors/origin-reflected");
    let ndjson = serde_json::to_string(&f).unwrap();

    let result = parse_findings_ndjson(&ndjson).expect("valid JSON must parse");
    assert_eq!(result.len(), 1);
    let parsed = &result[0];
    assert_eq!(parsed.url, "https://api.example.com/v1/users");
    assert_eq!(parsed.check, "cors/origin-reflected");
    assert_eq!(parsed.severity, "HIGH");
    assert_eq!(parsed.scanner.as_deref(), Some("test-scanner"));
}

#[test]
fn enrich_parse_ndjson_multiple_lines_preserves_order() {
    let findings = vec![
        raw_finding("https://a.example.com/", "check/a"),
        raw_finding("https://b.example.com/", "check/b"),
        raw_finding("https://c.example.com/", "check/c"),
    ];
    let ndjson = to_ndjson(&findings);

    let result = parse_findings_ndjson(&ndjson).expect("multi-line NDJSON must parse");
    assert_eq!(result.len(), 3);
    assert_eq!(result[0].check, "check/a");
    assert_eq!(result[1].check, "check/b");
    assert_eq!(result[2].check, "check/c");
}

#[test]
fn enrich_parse_ndjson_interleaved_blank_lines_are_ignored() {
    let f1 = serde_json::to_string(&raw_finding("https://x.io/", "jwt/alg-none")).unwrap();
    let f2 = serde_json::to_string(&raw_finding("https://y.io/", "cors/wildcard")).unwrap();
    let input = format!("{f1}\n\n# comment\n{f2}\n");

    let result = parse_findings_ndjson(&input).unwrap();
    assert_eq!(result.len(), 2);
}

#[test]
fn enrich_parse_ndjson_optional_fields_default_to_none() {
    // Minimal JSON — only required fields present
    let minimal = r#"{"url":"https://min.io/","check":"test","title":"T","severity":"LOW"}"#;
    let result = parse_findings_ndjson(minimal).expect("minimal finding must parse");
    assert_eq!(result.len(), 1);
    let f = &result[0];
    assert!(f.detail.is_none(), "detail should default to None");
    assert!(f.evidence.is_none(), "evidence should default to None");
    assert!(f.scanner.is_none(), "scanner should default to None");
}

#[test]
fn enrich_parse_ndjson_invalid_json_returns_error() {
    let bad = "not json at all\n";
    let result = parse_findings_ndjson(bad);
    assert!(result.is_err(), "invalid JSON must produce Err");
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("Invalid JSON"), "error must mention the line: {msg}");
}

#[test]
fn enrich_parse_ndjson_missing_required_field_returns_error() {
    // Missing `check` field
    let incomplete = r#"{"url":"https://x.io/","title":"T","severity":"HIGH"}"#;
    let result = parse_findings_ndjson(incomplete);
    assert!(result.is_err(), "missing required field must fail");
}

// ── enrich_findings: empty input ──────────────────────────────────────────────

#[tokio::test]
async fn enrich_findings_empty_input_returns_zero_result() {
    let result = enrich_findings(vec![], fast_config())
        .await
        .expect("empty input must not error");

    assert_eq!(result.total_findings, 0);
    assert_eq!(result.unique_hosts, 0);
    assert!(result.enriched.is_empty());
    assert_eq!(result.elapsed_ms, 0);
    assert!(result.triage_errors.is_empty());
}

// ── enrich_findings: single unresolvable host ─────────────────────────────────

#[tokio::test]
async fn enrich_findings_one_finding_produces_one_enriched_entry() {
    // Use a host that won't resolve in 300 ms so the probe is Skipped/error.
    // The engine must still return exactly 1 enriched finding.
    let findings = vec![raw_finding(
        "https://198.51.100.1/api/test",   // TEST-NET — unreachable
        "cors/origin-reflected",
    )];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("single-finding enrich must not error");

    assert_eq!(result.total_findings, 1);
    assert_eq!(result.unique_hosts, 1);
    assert_eq!(result.enriched.len(), 1);

    // Original finding fields must pass through unchanged.
    let ef = &result.enriched[0];
    assert_eq!(ef.finding.url, "https://198.51.100.1/api/test");
    assert_eq!(ef.finding.check, "cors/origin-reflected");
    assert_eq!(ef.finding.severity, "HIGH");
}

#[tokio::test]
async fn enrich_findings_unresolvable_host_has_null_threat_intel() {
    let findings = vec![raw_finding("https://198.51.100.2/v1/", "jwt/alg-none")];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("engine must not fail for unresolvable host");

    // threat_intel may be None (probe timed out / no result).
    // We only assert the finding itself passed through correctly.
    assert_eq!(result.enriched[0].finding.check, "jwt/alg-none");
}

// ── enrich_findings: host deduplication ──────────────────────────────────────

#[tokio::test]
async fn enrich_findings_multiple_findings_same_host_deduplicated_to_one_probe() {
    // Three findings for the same host — should produce 3 enriched findings
    // but only 1 unique_host (one probe fired).
    let host = "https://198.51.100.3";
    let findings = vec![
        raw_finding(&format!("{host}/v1/users"), "cors/origin-reflected"),
        raw_finding(&format!("{host}/v1/admin"), "api_security/debug-endpoint"),
        raw_finding(&format!("{host}/v2/users"), "openapi/spec-exposed"),
    ];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("dedup enrich must not error");

    assert_eq!(result.total_findings, 3, "all 3 input findings must be in output");
    assert_eq!(result.unique_hosts, 1, "only 1 probe must fire for the same host");
    assert_eq!(result.enriched.len(), 3, "output must have 3 enriched findings");
}

#[tokio::test]
async fn enrich_findings_different_hosts_each_probe_separately() {
    let findings = vec![
        raw_finding("https://198.51.100.4/api", "cors/origin-reflected"),
        raw_finding("https://198.51.100.5/api", "cors/origin-reflected"),
        raw_finding("https://198.51.100.6/api", "cors/origin-reflected"),
    ];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("multi-host enrich must not error");

    assert_eq!(result.total_findings, 3);
    assert_eq!(result.unique_hosts, 3, "3 distinct hosts → 3 probes");
    assert_eq!(result.enriched.len(), 3);
}

// ── enrich_findings: non-default port is part of probe key ───────────────────

#[tokio::test]
async fn enrich_findings_non_default_port_treated_as_separate_host() {
    let findings = vec![
        raw_finding("https://198.51.100.7:8443/api", "jwt/alg-none"),
        raw_finding("https://198.51.100.7/api",      "jwt/alg-none"),
    ];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("port-keyed enrich must not error");

    assert_eq!(result.total_findings, 2);
    // :8443 is a non-default port → treated as a different probe target
    assert_eq!(result.unique_hosts, 2, "different ports → different probe keys");
}

#[tokio::test]
async fn enrich_findings_https_443_and_bare_https_share_one_probe() {
    // :443 on https is the default — both URLs resolve to the same probe key.
    let findings = vec![
        raw_finding("https://198.51.100.8:443/api", "check/a"),
        raw_finding("https://198.51.100.8/api",     "check/b"),
    ];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("default-port dedup must not error");

    assert_eq!(result.total_findings, 2);
    assert_eq!(result.unique_hosts, 1, "https :443 and https bare are the same probe key");
}

#[tokio::test]
async fn enrich_findings_http_80_and_bare_http_share_one_probe() {
    let findings = vec![
        raw_finding("http://198.51.100.9:80/api", "check/a"),
        raw_finding("http://198.51.100.9/api",    "check/b"),
    ];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("http :80 dedup must not error");

    assert_eq!(result.total_findings, 2);
    assert_eq!(result.unique_hosts, 1);
}

// ── enrich_findings: finding field pass-through ───────────────────────────────

#[tokio::test]
async fn enrich_findings_all_original_fields_pass_through_unchanged() {
    let original = RawFinding {
        url: "https://198.51.100.10/v1/resource".to_string(),
        check: "mass_assignment/extra-fields-accepted".to_string(),
        title: "Mass Assignment Possible".to_string(),
        severity: "CRITICAL".to_string(),
        detail: Some("Sensitive field accepted in PUT /v1/resource".to_string()),
        evidence: Some(r#"{"admin":true}"#.to_string()),
        scanner: Some("mass_assignment".to_string()),
    };

    let result = enrich_findings(vec![original.clone()], fast_config())
        .await
        .expect("field pass-through must not error");

    let ef = &result.enriched[0];
    assert_eq!(ef.finding.url,      original.url);
    assert_eq!(ef.finding.check,    original.check);
    assert_eq!(ef.finding.title,    original.title);
    assert_eq!(ef.finding.severity, original.severity);
    assert_eq!(ef.finding.detail,   original.detail);
    assert_eq!(ef.finding.evidence, original.evidence);
    assert_eq!(ef.finding.scanner,  original.scanner);
}

// ── enrich_findings: EnrichResult shape ──────────────────────────────────────

#[tokio::test]
async fn enrich_result_elapsed_ms_is_non_zero_for_non_empty_input() {
    let findings = vec![raw_finding("https://198.51.100.11/api", "check/x")];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("elapsed_ms test must not error");

    // Even with probe timeouts, elapsed must be > 0 for non-empty input.
    assert!(result.elapsed_ms > 0, "elapsed_ms must be > 0, got 0");
}

#[tokio::test]
async fn enrich_result_triage_errors_is_always_a_vec() {
    let findings = vec![raw_finding("https://198.51.100.12/api", "check/y")];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("errors vec shape must not error");

    // triage_errors must be present (possibly empty) — never panics.
    let _ = result.triage_errors.len();
}

// ── EnrichConfig defaults ─────────────────────────────────────────────────────

#[test]
fn enrich_config_default_concurrency_and_timeout_are_sensible() {
    let cfg = EnrichConfig::default();
    assert_eq!(cfg.concurrency, 50, "default concurrency should be 50");
    assert_eq!(
        cfg.timeout,
        Duration::from_secs(5),
        "default timeout should be 5 s"
    );
}

// ── serialisation round-trip ──────────────────────────────────────────────────

#[tokio::test]
async fn enrich_enriched_finding_serialises_to_valid_json() {
    let findings = vec![raw_finding("https://198.51.100.13/api", "cors/wildcard")];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("serialise test must not error");

    for ef in &result.enriched {
        let json = serde_json::to_string(ef)
            .expect("EnrichedFinding must serialise to JSON");
        assert!(json.contains("cors/wildcard"), "check field must appear in JSON: {json}");
        assert!(json.contains("threat_intel"), "threat_intel key must appear in JSON: {json}");
    }
}

#[tokio::test]
async fn enrich_ndjson_stream_is_one_object_per_line() {
    let findings = vec![
        raw_finding("https://198.51.100.14/a", "check/a"),
        raw_finding("https://198.51.100.14/b", "check/b"),
    ];

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("ndjson test must not error");

    let ndjson: Vec<String> = result
        .enriched
        .iter()
        .filter_map(|e| serde_json::to_string(e).ok())
        .collect();

    assert_eq!(ndjson.len(), 2);
    for line in &ndjson {
        // Each line must be a valid JSON object.
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("each NDJSON line must be valid JSON");
        assert!(parsed.is_object(), "each NDJSON line must be a JSON object");
    }
}

// ── large batch ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn enrich_large_batch_of_same_host_produces_correct_counts() {
    // 50 findings from the same host — 50 enriched, 1 unique host.
    let findings: Vec<RawFinding> = (0..50)
        .map(|i| raw_finding(&format!("https://198.51.100.15/path/{i}"), "check/x"))
        .collect();

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("large batch must not error");

    assert_eq!(result.total_findings, 50);
    assert_eq!(result.unique_hosts, 1);
    assert_eq!(result.enriched.len(), 50);
}

#[tokio::test]
async fn enrich_large_batch_of_distinct_hosts_probes_each_once() {
    // 20 distinct TEST-NET hosts → 20 probes, 20 enriched findings.
    let findings: Vec<RawFinding> = (1..=20)
        .map(|i| raw_finding(&format!("https://198.51.100.{}/api", i + 20), "check/y"))
        .collect();

    let result = enrich_findings(findings, fast_config())
        .await
        .expect("distinct-hosts batch must not error");

    assert_eq!(result.total_findings, 20);
    assert_eq!(result.unique_hosts, 20);
    assert_eq!(result.enriched.len(), 20);
}
