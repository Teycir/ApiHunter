//! Load past scan results from export directories.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{
    error::CapturedError,
    reports::{self, CapturedErrorRecord, Finding, ReportConfig, ReportMeta, ReportSummary, Reporter, Severity},
    runner::RunResult,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedScan {
    pub path: PathBuf,
    pub meta: ReportMeta,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
    pub errors: Vec<CapturedErrorRecord>,
}

/// Load a scan from an export directory containing findings.json or .ndjson file
pub fn load_scan(dir: impl AsRef<Path>) -> Result<LoadedScan> {
    let dir = dir.as_ref();
    
    // Try findings.json first (CLI auto-report format)
    let findings_path = dir.join("findings.json");
    if findings_path.exists() {
        return load_from_json(&findings_path, dir);
    }
    
    // Try .ndjson files (desktop export format)
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory {}", dir.display()))?;
    
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("ndjson") {
            return load_from_ndjson(&path, dir);
        }
    }
    
    anyhow::bail!("No findings.json or .ndjson file found in {}", dir.display())
}

fn load_from_json(path: &Path, dir: &Path) -> Result<LoadedScan> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    
    let doc: serde_json::Value = serde_json::from_str(&content)
        .context("Invalid JSON in findings.json")?;
    
    let meta: ReportMeta = serde_json::from_value(doc["meta"].clone())
        .context("Missing or invalid 'meta' field")?;
    
    let summary: ReportSummary = serde_json::from_value(doc["summary"].clone())
        .context("Missing or invalid 'summary' field")?;
    
    let findings: Vec<Finding> = serde_json::from_value(doc["findings"].clone())
        .context("Missing or invalid 'findings' field")?;
    
    let errors: Vec<CapturedErrorRecord> = serde_json::from_value(doc["errors"].clone())
        .unwrap_or_default();
    
    Ok(LoadedScan {
        path: dir.to_path_buf(),
        meta,
        summary,
        findings,
        errors,
    })
}

fn load_from_ndjson(path: &Path, dir: &Path) -> Result<LoadedScan> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    
    let mut meta: Option<ReportMeta> = None;
    let mut summary: Option<ReportSummary> = None;
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        
        let value: serde_json::Value = serde_json::from_str(line)
            .context("Invalid JSON line in NDJSON")?;
        
        // First line is meta+summary
        if let Some(typ) = value.get("type").and_then(|v| v.as_str()) {
            if typ == "meta" {
                meta = Some(serde_json::from_value(value["meta"].clone())
                    .context("Invalid meta in NDJSON")?);
                summary = Some(serde_json::from_value(value["summary"].clone())
                    .context("Invalid summary in NDJSON")?);
                continue;
            }
        }
        
        // Try to parse as Finding
        if value.get("check").is_some() {
            if let Ok(finding) = serde_json::from_value::<Finding>(value.clone()) {
                findings.push(finding);
                continue;
            }
        }
        
        // Try to parse as CapturedErrorRecord
        if value.get("kind").is_some() || value.get("message").is_some() {
            if let Ok(error) = serde_json::from_value::<CapturedErrorRecord>(value) {
                errors.push(error);
            }
        }
    }
    
    let meta = meta.context("No meta found in NDJSON")?;
    let summary = summary.context("No summary found in NDJSON")?;
    
    Ok(LoadedScan {
        path: dir.to_path_buf(),
        meta,
        summary,
        findings,
        errors,
    })
}

/// Process a loaded scan with filters and output it via reporter
pub fn process_loaded_scan(
    loaded: LoadedScan,
    min_severity: &Severity,
    baseline_path: Option<&Path>,
    report_cfg: ReportConfig,
) -> Result<i32> {
    let filtered_findings: Vec<_> = reports::filter_findings(&loaded.findings, min_severity)
        .into_iter()
        .cloned()
        .collect();

    let errors: Vec<_> = loaded.errors.iter().map(|rec| {
        CapturedError::from_str("loaded_scan", rec.url.clone(), &rec.message)
    }).collect();

    let mut result = RunResult {
        findings: filtered_findings,
        errors,
        scanned: 0,
        skipped: 0,
        elapsed: std::time::Duration::from_millis(loaded.meta.elapsed_ms as u64),
        metrics: loaded.meta.runtime_metrics.clone(),
    };

    if let Some(path) = baseline_path {
        let baseline = reports::load_baseline_keys(path)?;
        result.findings = reports::filter_new_findings(result.findings, &baseline);
    }

    let reporter = Reporter::new(report_cfg)?;
    reporter.write_run_result(&result);
    reporter.finalize();

    let summary = reports::build_summary(&result);
    Ok(reports::exit_code(&summary, min_severity))
}
