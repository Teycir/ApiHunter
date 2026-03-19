//! Automatic report saving to ~/Documents/ApiHunterReports with timestamped folders.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use chrono::Local;
use tracing::info;

use crate::{reports::ReportDocument, runner::RunResult};

/// Create a timestamped report directory and save both JSON and markdown summary.
pub fn save_auto_report(
    result: &RunResult,
    doc: &ReportDocument,
    min_severity: &str,
) -> Result<PathBuf> {
    let base_dir = get_reports_base_dir()?;
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let report_dir = base_dir.join(timestamp);

    fs::create_dir_all(&report_dir).with_context(|| {
        format!(
            "Failed to create report directory: {}",
            report_dir.display()
        )
    })?;

    // Save JSON findings
    let json_path = report_dir.join("findings.json");
    let json_content =
        serde_json::to_string_pretty(doc).context("Failed to serialize report to JSON")?;
    fs::write(&json_path, json_content)
        .with_context(|| format!("Failed to write JSON report: {}", json_path.display()))?;

    // Save markdown summary
    let md_path = report_dir.join("summary.md");
    let md_content = generate_markdown_summary(doc, result, min_severity);
    fs::write(&md_path, md_content)
        .with_context(|| format!("Failed to write markdown summary: {}", md_path.display()))?;

    // Save raw scan log
    let log_path = report_dir.join("scan.log");
    let log_content = generate_scan_log(result);
    fs::write(&log_path, log_content)
        .with_context(|| format!("Failed to write scan log: {}", log_path.display()))?;

    info!("Auto-saved report to: {}", report_dir.display());

    Ok(report_dir)
}

/// Get the base reports directory: ~/Documents/ApiHunterReports
fn get_reports_base_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let base = home.join("Documents").join("ApiHunterReports");

    if !base.exists() {
        fs::create_dir_all(&base).with_context(|| {
            format!(
                "Failed to create base reports directory: {}",
                base.display()
            )
        })?;
    }

    Ok(base)
}

/// Generate a markdown summary of the scan results.
fn generate_markdown_summary(
    doc: &ReportDocument,
    _result: &RunResult,
    min_severity: &str,
) -> String {
    let mut md = String::new();

    md.push_str("# ApiHunter Scan Report\n\n");

    // Metadata
    md.push_str("## Scan Information\n\n");
    md.push_str(&format!(
        "- **Generated**: {}\n",
        doc.meta.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    md.push_str(&format!(
        "- **Duration**: {:.2}s\n",
        doc.meta.elapsed_ms as f64 / 1000.0
    ));
    md.push_str(&format!(
        "- **Scanner Version**: {}\n",
        doc.meta.scanner_ver
    ));
    md.push_str(&format!("- **URLs Scanned**: {}\n", doc.meta.scanned));
    md.push_str(&format!("- **URLs Skipped**: {}\n", doc.meta.skipped));
    md.push_str(&format!(
        "- **HTTP Requests**: {}\n",
        doc.meta.runtime_metrics.http_requests
    ));
    md.push_str(&format!(
        "- **HTTP Retries**: {}\n",
        doc.meta.runtime_metrics.http_retries
    ));
    md.push_str(&format!("- **Min Severity Filter**: {}\n\n", min_severity));

    if !doc.meta.runtime_metrics.scanner_findings.is_empty() {
        md.push_str("### Runtime Scanner Counters\n\n");
        md.push_str("| Scanner | Findings | Errors |\n");
        md.push_str("|---------|----------|--------|\n");
        for (scanner, finding_count) in &doc.meta.runtime_metrics.scanner_findings {
            let error_count = doc
                .meta
                .runtime_metrics
                .scanner_errors
                .get(scanner)
                .copied()
                .unwrap_or(0);
            md.push_str(&format!(
                "| `{}` | {} | {} |\n",
                scanner, finding_count, error_count
            ));
        }
        md.push('\n');
    }

    // Summary
    md.push_str("## Summary\n\n");
    md.push_str("| Severity | Count |\n");
    md.push_str("|----------|----------|\n");
    md.push_str(&format!("| 🔴 Critical | {} |\n", doc.summary.critical));
    md.push_str(&format!("| 🟠 High | {} |\n", doc.summary.high));
    md.push_str(&format!("| 🟡 Medium | {} |\n", doc.summary.medium));
    md.push_str(&format!("| 🔵 Low | {} |\n", doc.summary.low));
    md.push_str(&format!("| ⚪ Info | {} |\n", doc.summary.info));
    md.push_str(&format!("| **Total** | **{}** |\n\n", doc.summary.total));

    if doc.summary.errors > 0 {
        md.push_str(&format!("⚠️ **Errors**: {}\n\n", doc.summary.errors));
    }

    // Findings by severity
    if !doc.findings.is_empty() {
        md.push_str("## Findings by Severity\n\n");

        for severity in ["Critical", "High", "Medium", "Low", "Info"] {
            let findings: Vec<_> = doc
                .findings
                .iter()
                .filter(|f| f.severity.to_string() == severity)
                .collect();

            if !findings.is_empty() {
                let emoji = match severity {
                    "Critical" => "🔴",
                    "High" => "🟠",
                    "Medium" => "🟡",
                    "Low" => "🔵",
                    _ => "⚪",
                };

                md.push_str(&format!(
                    "### {} {} ({} findings)\n\n",
                    emoji,
                    severity,
                    findings.len()
                ));

                for finding in findings {
                    md.push_str(&format!("#### {}\n\n", finding.title));
                    md.push_str(&format!("- **URL**: `{}`\n", finding.url));
                    md.push_str(&format!("- **Check**: `{}`\n", finding.check));
                    md.push_str(&format!("- **Scanner**: {}\n", finding.scanner));
                    md.push_str(&format!("- **Detail**: {}\n", finding.detail));

                    if let Some(ref evidence) = finding.evidence {
                        md.push_str(&format!("- **Evidence**: `{}`\n", evidence));
                    }

                    if let Some(ref remediation) = finding.remediation {
                        md.push_str(&format!("- **Remediation**: {}\n", remediation));
                    }

                    md.push('\n');
                }
            }
        }
    }

    // Errors
    if !doc.errors.is_empty() {
        md.push_str("## Errors\n\n");

        for error in &doc.errors {
            md.push_str(&format!("- **{}**: {}", error.kind, error.message));
            if let Some(ref url) = error.url {
                md.push_str(&format!(" (URL: `{}`)", url));
            }
            md.push('\n');
        }
        md.push('\n');
    }

    // Footer
    md.push_str("---\n\n");
    md.push_str("*Generated by ApiHunter - API Security Scanner*\n");

    md
}

/// Generate a detailed scan log with all URLs, errors, and metadata.
fn generate_scan_log(result: &RunResult) -> String {
    let mut log = String::new();

    log.push_str("ApiHunter Scan Log\n");
    log.push_str("==================\n\n");
    log.push_str(&format!(
        "Scan Duration: {:.2}s\n",
        result.elapsed.as_secs_f64()
    ));
    log.push_str(&format!("URLs Scanned: {}\n", result.scanned));
    log.push_str(&format!("URLs Skipped: {}\n", result.skipped));
    log.push_str(&format!("Total Findings: {}\n\n", result.findings.len()));
    log.push_str(&format!(
        "HTTP Requests: {}\n",
        result.metrics.http_requests
    ));
    log.push_str(&format!(
        "HTTP Retries: {}\n\n",
        result.metrics.http_retries
    ));

    if !result.metrics.scanner_findings.is_empty() {
        log.push_str("Scanner Counters:\n");
        for (scanner, finding_count) in &result.metrics.scanner_findings {
            let error_count = result
                .metrics
                .scanner_errors
                .get(scanner)
                .copied()
                .unwrap_or(0);
            log.push_str(&format!(
                "  - {}: findings={}, errors={}\n",
                scanner, finding_count, error_count
            ));
        }
        log.push('\n');
    }

    // All findings with full details
    if !result.findings.is_empty() {
        log.push_str(&format!("FINDINGS ({})\n", result.findings.len()));
        log.push_str(&format!("{}\n\n", "=".repeat(80)));
        for (i, finding) in result.findings.iter().enumerate() {
            log.push_str(&format!(
                "[{}] {} - {}\n",
                i + 1,
                finding.severity,
                finding.title
            ));
            log.push_str(&format!("    URL: {}\n", finding.url));
            log.push_str(&format!("    Check: {}\n", finding.check));
            log.push_str(&format!("    Scanner: {}\n", finding.scanner));
            log.push_str(&format!("    Detail: {}\n", finding.detail));
            if let Some(ref evidence) = finding.evidence {
                log.push_str(&format!("    Evidence: {}\n", evidence));
            }
            if let Some(ref remediation) = finding.remediation {
                log.push_str(&format!("    Remediation: {}\n", remediation));
            }
            log.push_str(&format!(
                "    Timestamp: {}\n",
                finding.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
            ));
            log.push('\n');
        }
    }

    // All errors
    if !result.errors.is_empty() {
        log.push_str(&format!("\nERRORS ({})\n", result.errors.len()));
        log.push_str(&format!("{}\n\n", "=".repeat(80)));
        for (i, error) in result.errors.iter().enumerate() {
            log.push_str(&format!(
                "[{}] {} - {}\n",
                i + 1,
                error.error_type,
                error.message
            ));
            if let Some(ref url) = error.url {
                log.push_str(&format!("    URL: {}\n", url));
            }
            log.push_str(&format!("    Timestamp: {}\n", error.timestamp));
            log.push('\n');
        }
    }

    log.push_str(&format!("\n{}\n", "=".repeat(80)));
    log.push_str("End of scan log\n");

    log
}
