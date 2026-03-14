// tests/reports.rs
//
// Report helpers and output tests.

use std::io::Read;
use std::time::Duration;

use tempfile::NamedTempFile;

use api_scanner::reports::{
    dedup_findings, exit_code, filter_findings, Finding, ReportConfig, ReportFormat, ReportSummary,
    Reporter, Severity,
};
use api_scanner::runner::RunResult;

// ── Severity ordering ────────────────────────────────────────────────────────

#[test]
fn severity_rank_is_monotone() {
    assert!(Severity::Critical.rank() > Severity::High.rank());
    assert!(Severity::High.rank() > Severity::Medium.rank());
    assert!(Severity::Medium.rank() > Severity::Low.rank());
    assert!(Severity::Low.rank() > Severity::Info.rank());
}

#[test]
fn severity_display_round_trips() {
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        // label().trim() must equal Display output
        assert_eq!(sev.label().trim(), sev.to_string());
    }
}

#[test]
fn severity_serde_round_trips() {
    let json = serde_json::to_string(&Severity::High).unwrap();
    assert_eq!(json, r#""HIGH""#);
    let back: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, Severity::High);
}

// ── Finding builders ─────────────────────────────────────────────────────────

#[test]
fn finding_builder_sets_optional_fields() {
    let f = Finding::new(
        "https://example.com",
        "cors.wildcard",
        "Wildcard CORS",
        Severity::High,
        "Access-Control-Allow-Origin: *",
        "cors",
    )
    .with_evidence("acao: *")
    .with_remediation("Restrict CORS origin")
    .with_metadata(serde_json::json!({"cve": "N/A"}));

    assert_eq!(f.evidence.as_deref(), Some("acao: *"));
    assert_eq!(f.remediation.as_deref(), Some("Restrict CORS origin"));
    assert!(f.metadata.is_some());
}

#[test]
fn finding_serialises_without_none_fields() {
    let f = Finding::new(
        "https://example.com",
        "csp.missing",
        "No CSP header",
        Severity::Medium,
        "Header absent",
        "csp",
    );

    let v: serde_json::Value = serde_json::to_value(&f).unwrap();
    assert!(!v.as_object().unwrap().contains_key("evidence"));
    assert!(!v.as_object().unwrap().contains_key("remediation"));
    assert!(!v.as_object().unwrap().contains_key("metadata"));
}

// ── Deduplication & filtering ────────────────────────────────────────────────

#[test]
fn dedup_keeps_highest_severity() {
    let make = |sev: Severity| {
        Finding::new(
            "https://example.com",
            "cors.wildcard",
            "title",
            sev,
            "detail",
            "cors",
        )
    };

    let findings = vec![make(Severity::Low), make(Severity::Critical), make(Severity::High)];
    let deduped = dedup_findings(findings);

    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].severity, Severity::Critical);
}

#[test]
fn dedup_preserves_distinct_checks() {
    let make = |check: &str| {
        Finding::new(
            "https://example.com",
            check,
            "title",
            Severity::High,
            "detail",
            "scanner",
        )
    };

    let findings = vec![make("cors.wildcard"), make("csp.missing"), make("cors.wildcard")];
    let deduped = dedup_findings(findings);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn filter_findings_respects_threshold() {
    let findings = vec![
        Finding::new("u", "a", "t", Severity::Critical, "d", "s"),
        Finding::new("u", "b", "t", Severity::Low, "d", "s"),
        Finding::new("u", "c", "t", Severity::Info, "d", "s"),
    ];

    let filtered = filter_findings(&findings, &Severity::High);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].severity, Severity::Critical);
}

// ── Exit code logic ──────────────────────────────────────────────────────────

#[test]
fn exit_code_clean_run() {
    let s = ReportSummary::default();
    assert_eq!(exit_code(&s, &Severity::High), 0);
}

#[test]
fn exit_code_findings_only() {
    let s = ReportSummary {
        high: 1,
        total: 1,
        ..Default::default()
    };
    assert_eq!(exit_code(&s, &Severity::High), 1);
}

#[test]
fn exit_code_errors_only() {
    let s = ReportSummary {
        errors: 3,
        ..Default::default()
    };
    assert_eq!(exit_code(&s, &Severity::High), 2);
}

#[test]
fn exit_code_findings_and_errors() {
    let s = ReportSummary {
        critical: 1,
        total: 1,
        errors: 1,
        ..Default::default()
    };
    assert_eq!(exit_code(&s, &Severity::High), 3);
}

#[test]
fn exit_code_below_threshold_is_clean() {
    // Only INFO findings, threshold is HIGH → clean exit
    let s = ReportSummary {
        info: 5,
        total: 5,
        ..Default::default()
    };
    assert_eq!(exit_code(&s, &Severity::High), 0);
}

// ── File output ──────────────────────────────────────────────────────────────

#[test]
fn reporter_writes_pretty_json_to_file() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let cfg = ReportConfig {
        format: ReportFormat::Pretty,
        output_path: Some(path.clone()),
        print_summary: false,
        quiet: true,
    };

    let reporter = Reporter::new(cfg).unwrap();
    let result = mock_run_result();

    reporter.write_run_result(&result);
    reporter.finalize();

    let mut content = String::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_string(&mut content)
        .unwrap();

    let doc: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert!(doc.get("findings").is_some());
    assert!(doc.get("summary").is_some());
    assert_eq!(doc["summary"]["total"], 1);
}

#[test]
fn reporter_writes_ndjson_to_file() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let cfg = ReportConfig {
        format: ReportFormat::Ndjson,
        output_path: Some(path.clone()),
        print_summary: false,
        quiet: true,
    };

    let reporter = Reporter::new(cfg).unwrap();
    let result = mock_run_result();

    reporter.write_run_result(&result);
    reporter.finalize();

    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // First line: meta+summary header
    let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(header["type"], "meta");

    // Second line: the single finding
    let finding: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(finding["check"], "cors.wildcard");
}

#[test]
fn flush_finding_appends_in_ndjson_mode() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let cfg = ReportConfig {
        format: ReportFormat::Ndjson,
        output_path: Some(path.clone()),
        print_summary: false,
        quiet: true,
    };

    let reporter = Reporter::new(cfg).unwrap();
    let finding = Finding::new(
        "https://example.com",
        "cors.wildcard",
        "Wildcard CORS",
        Severity::High,
        "detail",
        "cors",
    );

    reporter.flush_finding(&finding);
    reporter.finalize();

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(!content.is_empty());
    let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(v["check"], "cors.wildcard");
}

#[test]
fn flush_finding_is_noop_in_pretty_mode() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let cfg = ReportConfig {
        format: ReportFormat::Pretty,
        output_path: Some(path.clone()),
        print_summary: false,
        quiet: true,
    };

    let reporter = Reporter::new(cfg).unwrap();
    let finding = Finding::new(
        "https://example.com",
        "csp.missing",
        "No CSP",
        Severity::Medium,
        "detail",
        "csp",
    );

    reporter.flush_finding(&finding);
    reporter.finalize();

    // File should be empty — flush_finding is a no-op in Pretty mode
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.is_empty());
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn mock_run_result() -> RunResult {
    RunResult {
        findings: vec![Finding::new(
            "https://example.com",
            "cors.wildcard",
            "Wildcard CORS",
            Severity::High,
            "Access-Control-Allow-Origin: *",
            "cors",
        )],
        errors: vec![],
        elapsed: Duration::from_millis(420),
        scanned: 1,
        skipped: 0,
    }
}
