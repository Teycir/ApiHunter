//! Reporting layer.
//!
//! Responsibilities:
//!   1. Define the canonical [`Finding`] and [`Severity`] types used project-wide.
//!   2. Serialise a completed [`RunResult`] to JSON (pretty or NDJSON).
//!   3. Write reports to stdout, a file, or both.
//!   4. Emit a human-readable summary to the tracing subscriber.
//!   5. Optionally flush partial results periodically (streaming mode).

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    error::CapturedError,
    runner::RunResult,
};

// ── Severity ───────────────────────────────────────────────────────────────────

/// Unified severity scale shared by every scanner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    #[default]
    Info,
}

impl Severity {
    /// Numeric rank used for sorting (higher = more severe).
    #[inline]
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High     => 3,
            Severity::Medium   => 2,
            Severity::Low      => 1,
            Severity::Info     => 0,
        }
    }

    /// CSS / ANSI colour label for terminal output.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High     => "HIGH    ",
            Severity::Medium   => "MEDIUM  ",
            Severity::Low      => "LOW     ",
            Severity::Info     => "INFO    ",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label().trim())
    }
}

// ── Finding ────────────────────────────────────────────────────────────────────

/// A single security or informational observation produced by a scanner.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Finding {
    /// Canonical URL that was scanned.
    pub url: String,

    /// Machine-readable slug identifying the check (e.g. `"cors.wildcard"`).
    pub check: String,

    /// Short, human-readable title.
    pub title: String,

    /// Severity classification.
    pub severity: Severity,

    /// Full description — what was found and why it matters.
    pub detail: String,

    /// The raw evidence: header value, JSON snippet, etc.
    /// `None` when no meaningful snippet is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,

    /// Concrete remediation advice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,

    /// Which scanner produced this finding (e.g. `"cors"`, `"csp"`).
    pub scanner: String,

    /// Wall-clock time when the finding was recorded (UTC).
    pub timestamp: DateTime<Utc>,

    /// Optional extra fields scanners may attach (request IDs, CVE refs, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl Finding {
    /// Convenience constructor — `timestamp` is set to `Utc::now()`.
    pub fn new(
        url:      impl Into<String>,
        check:    impl Into<String>,
        title:    impl Into<String>,
        severity: Severity,
        detail:   impl Into<String>,
        scanner:  impl Into<String>,
    ) -> Self {
        Self {
            url:       url.into(),
            check:     check.into(),
            title:     title.into(),
            severity,
            detail:    detail.into(),
            scanner:   scanner.into(),
            timestamp: Utc::now(),
            ..Default::default()
        }
    }

    /// Builder: attach raw evidence.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    /// Builder: attach remediation advice.
    #[must_use]
    pub fn with_remediation(mut self, rem: impl Into<String>) -> Self {
        self.remediation = Some(rem.into());
        self
    }

    /// Builder: attach arbitrary JSON metadata.
    #[must_use]
    pub fn with_metadata(mut self, meta: serde_json::Value) -> Self {
        self.metadata = Some(meta);
        self
    }
}

// ── ReportConfig ──────────────────────────────────────────────────────────────

/// Controls how the report is written.
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Write pretty-printed JSON (default) or one object per line (NDJSON).
    pub format: ReportFormat,

    /// If `Some`, write the full report to this path in addition to stdout.
    pub output_path: Option<PathBuf>,

    /// If `true`, also print a human-readable summary table to stdout.
    pub print_summary: bool,

    /// If `true`, suppress the findings list from stdout (file only).
    pub quiet: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format:        ReportFormat::Pretty,
            output_path:   None,
            print_summary: true,
            quiet:         false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReportFormat {
    /// Single JSON object — suitable for dashboards, CI artefacts.
    #[default]
    Pretty,
    /// One `Finding` JSON object per line — suitable for `jq` pipelines.
    Ndjson,
}

// ── Full report document ───────────────────────────────────────────────────────

/// The complete, serialisable report document written to disk / stdout.
#[derive(Debug, Serialize)]
pub struct ReportDocument {
    pub meta:     ReportMeta,
    pub summary:  ReportSummary,
    pub findings: Vec<Finding>,
    pub errors:   Vec<CapturedErrorRecord>,
}

/// Top-level metadata about the run.
#[derive(Debug, Serialize)]
pub struct ReportMeta {
    pub generated_at: DateTime<Utc>,
    pub elapsed_ms:   u128,
    pub scanned:      usize,
    pub skipped:      usize,
    pub scanner_ver:  &'static str,
}

/// Counts by severity — useful at a glance without reading all findings.
#[derive(Debug, Serialize, Default)]
pub struct ReportSummary {
    pub total:    usize,
    pub critical: usize,
    pub high:     usize,
    pub medium:   usize,
    pub low:      usize,
    pub info:     usize,
    pub errors:   usize,
}

/// A serialisable wrapper around [`CapturedError`].
#[derive(Debug, Serialize)]
pub struct CapturedErrorRecord {
    pub url:     Option<String>,
    pub kind:    String,
    pub message: String,
}

impl From<&CapturedError> for CapturedErrorRecord {
    fn from(e: &CapturedError) -> Self {
        Self {
            url:     e.url.clone(),
            kind:    format!("{:?}", e.kind),
            message: e.message.clone(),
        }
    }
}

// ── Reporter ──────────────────────────────────────────────────────────────────

/// Stateful reporter that can also act as a streaming sink for partial flushes.
pub struct Reporter {
    cfg:          ReportConfig,
    /// Buffered writer for the output file (if configured).
    file_writer:  Option<Arc<Mutex<BufWriter<File>>>>,
}

impl Reporter {
    /// Create a new reporter, opening the output file (truncating) if needed.
    pub fn new(cfg: ReportConfig) -> std::io::Result<Self> {
        let file_writer = if let Some(ref path) = cfg.output_path {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?;
            Some(Arc::new(Mutex::new(BufWriter::new(file))))
        } else {
            None
        };

        Ok(Self { cfg, file_writer })
    }

    // ── Main entry point ─────────────────────────────────────────────────────

    /// Serialise and write a completed run.  Always returns `Ok` — errors are
    /// logged via `tracing` rather than propagated (non-fatal for the scan).
    pub fn write_run_result(&self, result: &RunResult) {
        let doc = build_document(result);

        match self.cfg.format {
            ReportFormat::Pretty => self.write_pretty(&doc),
            ReportFormat::Ndjson => self.write_ndjson(&doc),
        }

        if self.cfg.print_summary {
            print_summary_table(&doc.summary, result.elapsed);
        }
    }

    // ── Streaming / partial flush ────────────────────────────────────────────

    /// Append a single [`Finding`] immediately (NDJSON only).
    ///
    /// Useful when scanners emit findings progressively rather than waiting for
    /// the full run to complete.  In `Pretty` mode this is a no-op (the full
    /// document must be written atomically).
    pub fn flush_finding(&self, finding: &Finding) {
        if self.cfg.format != ReportFormat::Ndjson {
            return;
        }

        match serde_json::to_string(finding) {
            Ok(line) => {
                self.write_line_to_file(&line);
                if !self.cfg.quiet {
                    println!("{line}");
                }
            }
            Err(e) => {
                error!("Failed to serialise finding for streaming flush: {e}");
            }
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn write_pretty(&self, doc: &ReportDocument) {
        match serde_json::to_string_pretty(doc) {
            Ok(json) => {
                // Write to file first (more important), then stdout
                self.write_line_to_file(&json);

                if !self.cfg.quiet {
                    println!("{json}");
                }
            }
            Err(e) => error!("Failed to serialise report: {e}"),
        }
    }

    fn write_ndjson(&self, doc: &ReportDocument) {
        // Emit meta + summary as the first line so consumers can detect format
        let header = serde_json::json!({
            "type":    "meta",
            "meta":    &doc.meta,
            "summary": &doc.summary,
        });

        if let Ok(line) = serde_json::to_string(&header) {
            self.write_line_to_file(&line);
            if !self.cfg.quiet { println!("{line}"); }
        }

        for finding in &doc.findings {
            match serde_json::to_string(finding) {
                Ok(line) => {
                    self.write_line_to_file(&line);
                    if !self.cfg.quiet { println!("{line}"); }
                }
                Err(e) => error!("Failed to serialise finding: {e}"),
            }
        }

        for err in &doc.errors {
            match serde_json::to_string(err) {
                Ok(line) => {
                    self.write_line_to_file(&line);
                    if !self.cfg.quiet { println!("{line}"); }
                }
                Err(e) => error!("Failed to serialise error record: {e}"),
            }
        }
    }

    fn write_line_to_file(&self, content: &str) {
        let Some(ref writer) = self.file_writer else { return };

        match writer.lock() {
            Ok(mut w) => {
                if let Err(e) = writeln!(w, "{content}") {
                    error!("Failed to write to report file: {e}");
                }
            }
            Err(e) => error!("Report file writer lock poisoned: {e}"),
        }
    }

    /// Flush and sync the file writer.  Call once after the run completes.
    pub fn finalize(&self) {
        let Some(ref writer) = self.file_writer else { return };

        match writer.lock() {
            Ok(mut w) => {
                if let Err(e) = w.flush() {
                    error!("Failed to flush report file: {e}");
                } else if let Some(ref path) = self.cfg.output_path {
                    info!(path = %path.display(), "Report written");
                }
            }
            Err(e) => error!("Report file writer lock poisoned on finalize: {e}"),
        }
    }
}

// ── Document builders ─────────────────────────────────────────────────────────

fn build_document(result: &RunResult) -> ReportDocument {
    let summary  = build_summary(result);
    let errors: Vec<CapturedErrorRecord> =
        result.errors.iter().map(CapturedErrorRecord::from).collect();

    ReportDocument {
        meta: ReportMeta {
            generated_at: Utc::now(),
            elapsed_ms:   result.elapsed.as_millis(),
            scanned:      result.scanned,
            skipped:      result.skipped,
            scanner_ver:  env!("CARGO_PKG_VERSION"),
        },
        summary,
        findings: result.findings.clone(),
        errors,
    }
}

fn build_summary(result: &RunResult) -> ReportSummary {
    let mut s = ReportSummary {
        total:  result.findings.len(),
        errors: result.errors.len(),
        ..Default::default()
    };

    for f in &result.findings {
        match f.severity {
            Severity::Critical => s.critical += 1,
            Severity::High     => s.high     += 1,
            Severity::Medium   => s.medium   += 1,
            Severity::Low      => s.low      += 1,
            Severity::Info     => s.info     += 1,
        }
    }

    s
}

// ── Human-readable summary ────────────────────────────────────────────────────

/// Print a compact, aligned summary table to stdout via `tracing::info!`.
/// Uses plain `println!` so it always reaches the user regardless of log level.
fn print_summary_table(summary: &ReportSummary, elapsed: Duration) {
    println!();
    println!("╔══════════════════════════════╗");
    println!("║         SCAN SUMMARY         ║");
    println!("╠══════════════════════════════╣");
    println!("║  Findings      {:>5}          ║", summary.total);
    println!("║  ├─ Critical   {:>5}          ║", summary.critical);
    println!("║  ├─ High       {:>5}          ║", summary.high);
