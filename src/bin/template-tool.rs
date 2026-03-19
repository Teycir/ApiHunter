use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process,
};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_yaml::{Mapping, Value};

#[derive(Parser, Debug)]
#[command(name = "template-tool")]
#[command(about = "ApiHunter template tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Import a Nuclei YAML template into ApiHunter CVE TOML format.
    ImportNuclei(ImportNucleiArgs),
}

#[derive(Args, Debug)]
struct ImportNucleiArgs {
    /// Input Nuclei YAML template path.
    #[arg(long)]
    input: PathBuf,

    /// Output ApiHunter TOML template path.
    #[arg(long)]
    output: PathBuf,

    /// Optional check slug suffix (default: slugified template name).
    #[arg(long)]
    check_suffix: Option<String>,

    /// Optional source URL to preserve in `source` metadata.
    #[arg(long)]
    source_url: Option<String>,

    /// Optional context path hints (comma-separated).
    #[arg(long, value_delimiter = ',')]
    context_hints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TemplateFile {
    templates: Vec<Template>,
}

#[derive(Debug, Serialize)]
struct NameValue {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct Template {
    id: String,
    check: String,
    title: String,
    severity: String,
    detail: String,
    remediation: String,
    source: String,
    path: String,
    method: String,
    headers: Vec<NameValue>,
    match_headers: Vec<NameValue>,
    status_any_of: Vec<u16>,
    body_contains_any: Vec<String>,
    body_contains_all: Vec<String>,
    context_path_contains_any: Vec<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("template-tool error: {err:#}");
        process::exit(2);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ImportNuclei(args) => import_nuclei(args)?,
    }

    Ok(())
}

fn import_nuclei(args: ImportNucleiArgs) -> Result<()> {
    let raw = fs::read_to_string(&args.input)
        .with_context(|| format!("failed to read '{}'", args.input.display()))?;
    let yaml: Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse YAML '{}'", args.input.display()))?;

    let id = yaml
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing required top-level 'id'"))?
        .to_string();

    let info = yaml
        .get("info")
        .and_then(Value::as_mapping)
        .ok_or_else(|| anyhow::anyhow!("missing required top-level 'info' mapping"))?;

    let title = map_get_string(info, "name").unwrap_or_else(|| id.clone());
    let severity = map_get_string(info, "severity").unwrap_or_else(|| "info".to_string());
    let detail = map_get_string(info, "description")
        .unwrap_or_else(|| format!("Imported from Nuclei template {id}."));
    let remediation = map_get_string(info, "remediation").unwrap_or_else(|| {
        "Apply vendor patches and harden exposed management endpoints.".to_string()
    });

    let request = yaml
        .get("http")
        .and_then(Value::as_sequence)
        .and_then(|v| v.first())
        .and_then(Value::as_mapping)
        .ok_or_else(|| anyhow::anyhow!("missing required 'http[0]' request mapping"))?;

    let method = extract_method(request).unwrap_or_else(|| "GET".to_string());
    if method != "GET" {
        bail!("Only GET method is supported by ApiHunter CVE templates (found '{method}')");
    }

    let path = extract_path(request)?.ok_or_else(|| {
        anyhow::anyhow!(
            "failed to extract request path from 'path' list or first 'raw' request line"
        )
    })?;

    let headers = extract_headers(request);
    let (status_any_of, body_contains_any, body_contains_all) = extract_matchers(request);

    let source = args
        .source_url
        .unwrap_or_else(|| default_source_for_id(&id));

    let check_suffix = args
        .check_suffix
        .map(|s| slugify(&s))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| slugify(&title));
    let check = format!("cve/{}/{}", id.to_ascii_lowercase(), check_suffix);

    let context_hints = if args.context_hints.is_empty() {
        derive_context_hints(&path)
    } else {
        sanitize_hints(&args.context_hints)
    };

    let file = TemplateFile {
        templates: vec![Template {
            id,
            check,
            title,
            severity,
            detail,
            remediation,
            source,
            path,
            method,
            headers,
            match_headers: Vec::new(),
            status_any_of,
            body_contains_any,
            body_contains_all,
            context_path_contains_any: context_hints,
        }],
    };

    let rendered = toml::to_string_pretty(&file).context("failed to render TOML")?;
    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create '{}'", parent.display()))?;
        }
    }
    fs::write(&args.output, rendered)
        .with_context(|| format!("failed to write '{}'", args.output.display()))?;

    println!(
        "Wrote ApiHunter template: {} -> {}",
        args.input.display(),
        args.output.display()
    );

    Ok(())
}

fn map_get_string(map: &Mapping, key: &str) -> Option<String> {
    map.get(Value::String(key.to_string()))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn extract_method(req: &Mapping) -> Option<String> {
    if let Some(m) = req
        .get(Value::String("method".to_string()))
        .and_then(Value::as_str)
    {
        return Some(m.trim().to_ascii_uppercase());
    }

    // Fall back to parsing the first raw request line (e.g., "GET /path HTTP/1.1").
    req.get(Value::String("raw".to_string()))
        .and_then(Value::as_sequence)
        .and_then(|seq| seq.first())
        .and_then(Value::as_str)
        .and_then(|raw| raw.lines().next())
        .and_then(|line| line.split_whitespace().next())
        .map(|m| m.to_ascii_uppercase())
}

fn extract_path(req: &Mapping) -> Result<Option<String>> {
    if let Some(p) = req
        .get(Value::String("path".to_string()))
        .and_then(Value::as_sequence)
        .and_then(|seq| seq.first())
        .and_then(Value::as_str)
    {
        return Ok(Some(normalize_path(p)));
    }

    if let Some(raw_first_line) = req
        .get(Value::String("raw".to_string()))
        .and_then(Value::as_sequence)
        .and_then(|seq| seq.first())
        .and_then(Value::as_str)
        .and_then(|raw| raw.lines().next())
    {
        let parts = raw_first_line.split_whitespace().collect::<Vec<_>>();
        if parts.len() >= 2 {
            return Ok(Some(normalize_path(parts[1])));
        }
    }

    Ok(None)
}

fn normalize_path(input: &str) -> String {
    let mut path = input
        .trim()
        .replace("{{BaseURL}}", "")
        .replace("{{RootURL}}", "");

    if path.starts_with("http://") || path.starts_with("https://") {
        if let Ok(parsed) = url::Url::parse(&path) {
            path = parsed.path().to_string();
            if let Some(q) = parsed.query() {
                path.push('?');
                path.push_str(q);
            }
        }
    }

    if path.is_empty() {
        return "/".to_string();
    }

    if !path.starts_with('/') {
        if path.starts_with('?') {
            path = format!("/{path}");
        } else {
            path = format!("/{path}");
        }
    }

    path
}

fn extract_headers(req: &Mapping) -> Vec<NameValue> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    if let Some(map) = req
        .get(Value::String("headers".to_string()))
        .and_then(Value::as_mapping)
    {
        for (k, v) in map {
            let (Some(name), Some(value)) = (k.as_str(), v.as_str()) else {
                continue;
            };
            let name_trim = name.trim().to_string();
            if name_trim.is_empty() {
                continue;
            }
            let key_l = name_trim.to_ascii_lowercase();
            if seen.insert(key_l) {
                out.push(NameValue {
                    name: name_trim,
                    value: value.trim().to_string(),
                });
            }
        }
    }

    out
}

fn extract_matchers(req: &Mapping) -> (Vec<u16>, Vec<String>, Vec<String>) {
    let mut status = Vec::new();
    let mut any = Vec::new();
    let mut all = Vec::new();

    let mut status_seen = HashSet::new();
    let mut any_seen = HashSet::new();
    let mut all_seen = HashSet::new();

    let Some(matchers) = req
        .get(Value::String("matchers".to_string()))
        .and_then(Value::as_sequence)
    else {
        return (status, any, all);
    };

    for matcher in matchers {
        let Some(map) = matcher.as_mapping() else {
            continue;
        };

        let negative = map
            .get(Value::String("negative".to_string()))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if negative {
            continue;
        }

        let mtype = map
            .get(Value::String("type".to_string()))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();

        if mtype == "status" {
            if let Some(seq) = map
                .get(Value::String("status".to_string()))
                .and_then(Value::as_sequence)
            {
                for s in seq {
                    if let Some(code) = s.as_u64().and_then(|n| u16::try_from(n).ok()) {
                        if status_seen.insert(code) {
                            status.push(code);
                        }
                    }
                }
            }
            continue;
        }

        if mtype != "word" {
            continue;
        }

        let part = map
            .get(Value::String("part".to_string()))
            .and_then(Value::as_str)
            .unwrap_or("body")
            .to_ascii_lowercase();
        if !(part == "body" || part.starts_with("body_")) {
            continue;
        }

        let condition = map
            .get(Value::String("condition".to_string()))
            .and_then(Value::as_str)
            .unwrap_or("or")
            .to_ascii_lowercase();

        let Some(words) = map
            .get(Value::String("words".to_string()))
            .and_then(Value::as_sequence)
        else {
            continue;
        };

        for w in words {
            let Some(raw) = w.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
                continue;
            };
            if condition == "and" {
                let key = raw.to_ascii_lowercase();
                if all_seen.insert(key) {
                    all.push(raw.to_string());
                }
            } else {
                let key = raw.to_ascii_lowercase();
                if any_seen.insert(key) {
                    any.push(raw.to_string());
                }
            }
        }
    }

    (status, any, all)
}

fn derive_context_hints(path: &str) -> Vec<String> {
    let raw = path.split('?').next().unwrap_or(path);
    let mut hints = Vec::new();
    let mut seen = HashSet::new();

    for segment in raw.split('/').filter(|s| !s.trim().is_empty()) {
        let s = segment.trim();
        if s.starts_with('{') || s.starts_with("{{") {
            continue;
        }
        let hint = format!("/{}", s.to_ascii_lowercase());
        if seen.insert(hint.clone()) {
            hints.push(hint);
        }
        if hints.len() >= 4 {
            break;
        }
    }

    if hints.is_empty() {
        hints.push("/api".to_string());
    }

    hints
}

fn sanitize_hints(raw_hints: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in raw_hints {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut hint = trimmed.to_ascii_lowercase();
        if !hint.starts_with('/') {
            hint.insert(0, '/');
        }
        if seen.insert(hint.clone()) {
            out.push(hint);
        }
    }
    if out.is_empty() {
        vec!["/api".to_string()]
    } else {
        out
    }
}

fn default_source_for_id(id: &str) -> String {
    let year = id.split('-').nth(1).unwrap_or("unknown");
    format!("nuclei:http/cves/{year}/{id}.yaml")
}

fn slugify(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in raw.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[allow(dead_code)]
fn _is_yaml_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("yaml") | Some("yml")
    )
}
