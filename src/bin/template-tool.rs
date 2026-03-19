use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process,
};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use serde_yml::{Mapping, Value};

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
    preflight_requests: Vec<RequestStep>,
    match_headers: Vec<NameValue>,
    status_any_of: Vec<u16>,
    body_contains_any: Vec<String>,
    body_contains_all: Vec<String>,
    body_regex_any: Vec<String>,
    body_regex_all: Vec<String>,
    header_regex_any: Vec<String>,
    header_regex_all: Vec<String>,
    context_path_contains_any: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RequestStep {
    path: String,
    method: String,
    headers: Vec<NameValue>,
    expect_status_any_of: Vec<u16>,
}

struct RequestSelection<'a> {
    index: usize,
    request: &'a Mapping,
    method: String,
    path: String,
}

#[derive(Debug, Default)]
struct MatchersTranslation {
    status_any_of: Vec<u16>,
    body_contains_any: Vec<String>,
    body_contains_all: Vec<String>,
    match_headers: Vec<NameValue>,
    body_regex_any: Vec<String>,
    body_regex_all: Vec<String>,
    header_regex_any: Vec<String>,
    header_regex_all: Vec<String>,
}

const MAX_PREFLIGHT_STEPS: usize = 3;

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
    let yaml: Value = serde_yml::from_str(&raw)
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

    let http_requests = yaml
        .get("http")
        .and_then(Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("missing required top-level 'http' request list"))?;

    let selection = select_importable_request(http_requests)?;
    let preflight_requests = extract_preflight_steps(http_requests, selection.index)?;
    let headers = extract_headers(selection.request);
    let matchers = extract_matchers(selection.request);

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
        derive_context_hints(&selection.path)
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
            path: selection.path,
            method: selection.method,
            headers,
            preflight_requests,
            match_headers: matchers.match_headers,
            status_any_of: matchers.status_any_of,
            body_contains_any: matchers.body_contains_any,
            body_contains_all: matchers.body_contains_all,
            body_regex_any: matchers.body_regex_any,
            body_regex_all: matchers.body_regex_all,
            header_regex_any: matchers.header_regex_any,
            header_regex_all: matchers.header_regex_all,
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

fn select_importable_request(http_requests: &[Value]) -> Result<RequestSelection<'_>> {
    if http_requests.is_empty() {
        bail!("missing required 'http[0]' request mapping");
    }

    let mut first_non_get: Option<String> = None;
    let mut first_get_candidate: Option<RequestSelection<'_>> = None;

    for (idx, raw_req) in http_requests.iter().enumerate() {
        let Some(req) = raw_req.as_mapping() else {
            continue;
        };

        let method = extract_method(req).unwrap_or_else(|| "GET".to_string());
        if method != "GET" {
            if first_non_get.is_none() {
                first_non_get = Some(method);
            }
            continue;
        }

        let Some(path) = extract_path(req)? else {
            continue;
        };

        let candidate = RequestSelection {
            index: idx,
            request: req,
            method: "GET".to_string(),
            path,
        };

        if request_has_importable_matchers(req) {
            return Ok(candidate);
        }

        if first_get_candidate.is_none() {
            first_get_candidate = Some(candidate);
        }
    }

    if let Some(candidate) = first_get_candidate {
        return Ok(candidate);
    }

    if let Some(method) = first_non_get {
        bail!("Only GET method is supported by ApiHunter CVE templates (found '{method}')");
    }

    bail!("failed to extract request path from 'path' list or first 'raw' request line")
}

fn request_has_importable_matchers(req: &Mapping) -> bool {
    let m = extract_matchers(req);
    !m.status_any_of.is_empty()
        || !m.body_contains_any.is_empty()
        || !m.body_contains_all.is_empty()
        || !m.match_headers.is_empty()
        || !m.body_regex_any.is_empty()
        || !m.body_regex_all.is_empty()
        || !m.header_regex_any.is_empty()
        || !m.header_regex_all.is_empty()
}

fn extract_preflight_steps(
    http_requests: &[Value],
    selected_index: usize,
) -> Result<Vec<RequestStep>> {
    let mut steps = Vec::new();

    for raw_req in http_requests.iter().take(selected_index) {
        if steps.len() >= MAX_PREFLIGHT_STEPS {
            break;
        }

        let Some(req) = raw_req.as_mapping() else {
            continue;
        };
        let method = extract_method(req).unwrap_or_else(|| "GET".to_string());
        if !is_safe_chain_method(&method) {
            continue;
        }
        let Some(path) = extract_path(req)? else {
            continue;
        };

        let headers = extract_headers(req);
        let matchers = extract_matchers(req);

        steps.push(RequestStep {
            path,
            method,
            headers,
            expect_status_any_of: matchers.status_any_of,
        });
    }

    Ok(steps)
}

fn is_safe_chain_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
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
        .and_then(|seq| {
            seq.iter().find_map(|entry| {
                entry
                    .as_str()
                    .and_then(|raw| raw.lines().find(|line| !line.trim().is_empty()))
                    .and_then(|line| line.split_whitespace().next())
            })
        })
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
        .and_then(|seq| {
            seq.iter().find_map(|entry| {
                entry
                    .as_str()
                    .and_then(|raw| raw.lines().find(|line| !line.trim().is_empty()))
            })
        })
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
        path = format!("/{path}");
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

    if out.is_empty() {
        return extract_headers_from_raw(req);
    }

    out
}

fn extract_headers_from_raw(req: &Mapping) -> Vec<NameValue> {
    let Some(raw_entries) = req
        .get(Value::String("raw".to_string()))
        .and_then(Value::as_sequence)
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for entry in raw_entries {
        let Some(raw_block) = entry.as_str() else {
            continue;
        };

        let mut lines = raw_block.lines();
        let _ = lines.next(); // request line
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            let Some((name_raw, value_raw)) = trimmed.split_once(':') else {
                continue;
            };

            let name = name_raw.trim();
            let value = value_raw.trim();
            if name.is_empty() || value.is_empty() {
                continue;
            }
            if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
                continue;
            }

            let key = name.to_ascii_lowercase();
            if seen.insert(key) {
                out.push(NameValue {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
        }
    }

    out
}

fn extract_matchers(req: &Mapping) -> MatchersTranslation {
    let mut out = MatchersTranslation::default();
    let mut status_seen = HashSet::new();
    let mut body_any_seen = HashSet::new();
    let mut body_all_seen = HashSet::new();
    let mut header_seen = HashSet::new();
    let mut body_regex_any_seen = HashSet::new();
    let mut body_regex_all_seen = HashSet::new();
    let mut header_regex_any_seen = HashSet::new();
    let mut header_regex_all_seen = HashSet::new();

    let Some(matchers) = req
        .get(Value::String("matchers".to_string()))
        .and_then(Value::as_sequence)
    else {
        return out;
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
                            out.status_any_of.push(code);
                        }
                    }
                }
            }
            continue;
        }

        let condition = map
            .get(Value::String("condition".to_string()))
            .and_then(Value::as_str)
            .unwrap_or("or")
            .to_ascii_lowercase();
        let condition_is_all = condition == "and";

        if mtype == "word" {
            let part = map
                .get(Value::String("part".to_string()))
                .and_then(Value::as_str)
                .unwrap_or("body")
                .to_ascii_lowercase();

            if part == "header" || part == "all_headers" || part.starts_with("header_") {
                if let Some(words) = map
                    .get(Value::String("words".to_string()))
                    .and_then(Value::as_sequence)
                {
                    for w in words {
                        let Some(raw) = w.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
                            continue;
                        };
                        if let Some((name, value)) = parse_header_pair(raw) {
                            let key = format!(
                                "{}:{}",
                                name.to_ascii_lowercase(),
                                value.to_ascii_lowercase()
                            );
                            if header_seen.insert(key) {
                                out.match_headers.push(NameValue { name, value });
                            }
                        } else {
                            let pattern = contains_literal_regex(raw);
                            if condition_is_all {
                                if header_regex_all_seen.insert(pattern.clone()) {
                                    out.header_regex_all.push(pattern);
                                }
                            } else if header_regex_any_seen.insert(pattern.clone()) {
                                out.header_regex_any.push(pattern);
                            }
                        }
                    }
                }
                continue;
            }

            if !(part == "body" || part.starts_with("body_")) {
                continue;
            }

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
                if condition_is_all {
                    let key = raw.to_ascii_lowercase();
                    if body_all_seen.insert(key) {
                        out.body_contains_all.push(raw.to_string());
                    }
                } else {
                    let key = raw.to_ascii_lowercase();
                    if body_any_seen.insert(key) {
                        out.body_contains_any.push(raw.to_string());
                    }
                }
            }
            continue;
        }

        if mtype == "regex" {
            let part = map
                .get(Value::String("part".to_string()))
                .and_then(Value::as_str)
                .unwrap_or("body")
                .to_ascii_lowercase();
            let Some(regexes) = map
                .get(Value::String("regex".to_string()))
                .and_then(Value::as_sequence)
            else {
                continue;
            };

            for r in regexes {
                let Some(pattern) = r.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
                    continue;
                };
                if part == "header" || part == "all_headers" || part.starts_with("header_") {
                    if condition_is_all {
                        if header_regex_all_seen.insert(pattern.to_string()) {
                            out.header_regex_all.push(pattern.to_string());
                        }
                    } else if header_regex_any_seen.insert(pattern.to_string()) {
                        out.header_regex_any.push(pattern.to_string());
                    }
                } else if part == "body" || part.starts_with("body_") {
                    if condition_is_all {
                        if body_regex_all_seen.insert(pattern.to_string()) {
                            out.body_regex_all.push(pattern.to_string());
                        }
                    } else if body_regex_any_seen.insert(pattern.to_string()) {
                        out.body_regex_any.push(pattern.to_string());
                    }
                }
            }
            continue;
        }

        if mtype == "dsl" {
            let Some(expressions) = map
                .get(Value::String("dsl".to_string()))
                .and_then(Value::as_sequence)
            else {
                continue;
            };

            for expr in expressions {
                let Some(expr_raw) = expr.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
                    continue;
                };

                for caps in DSL_STATUS_EQ_RE.captures_iter(expr_raw) {
                    let Some(code) = caps.get(1).and_then(|m| m.as_str().parse::<u16>().ok())
                    else {
                        continue;
                    };
                    if status_seen.insert(code) {
                        out.status_any_of.push(code);
                    }
                }

                for caps in DSL_CONTAINS_BODY_RE.captures_iter(expr_raw) {
                    let Some(token) = caps.get(1).map(|m| m.as_str().trim()) else {
                        continue;
                    };
                    if token.is_empty() {
                        continue;
                    }
                    if condition_is_all {
                        let key = token.to_ascii_lowercase();
                        if body_all_seen.insert(key) {
                            out.body_contains_all.push(token.to_string());
                        }
                    } else {
                        let key = token.to_ascii_lowercase();
                        if body_any_seen.insert(key) {
                            out.body_contains_any.push(token.to_string());
                        }
                    }
                }

                for caps in DSL_REGEX_BODY_RE.captures_iter(expr_raw) {
                    let Some(pattern) = caps.get(1).map(|m| m.as_str().trim()) else {
                        continue;
                    };
                    if pattern.is_empty() {
                        continue;
                    }
                    if condition_is_all {
                        if body_regex_all_seen.insert(pattern.to_string()) {
                            out.body_regex_all.push(pattern.to_string());
                        }
                    } else if body_regex_any_seen.insert(pattern.to_string()) {
                        out.body_regex_any.push(pattern.to_string());
                    }
                }

                for caps in DSL_CONTAINS_HEADERS_RE.captures_iter(expr_raw) {
                    let Some(token) = caps.get(1).map(|m| m.as_str().trim()) else {
                        continue;
                    };
                    if token.is_empty() {
                        continue;
                    }
                    if let Some((name, value)) = parse_header_pair(token) {
                        let key = format!(
                            "{}:{}",
                            name.to_ascii_lowercase(),
                            value.to_ascii_lowercase()
                        );
                        if header_seen.insert(key) {
                            out.match_headers.push(NameValue { name, value });
                        }
                    } else {
                        let pattern = contains_literal_regex(token);
                        if condition_is_all {
                            if header_regex_all_seen.insert(pattern.clone()) {
                                out.header_regex_all.push(pattern);
                            }
                        } else if header_regex_any_seen.insert(pattern.clone()) {
                            out.header_regex_any.push(pattern);
                        }
                    }
                }

                for caps in DSL_REGEX_HEADERS_RE.captures_iter(expr_raw) {
                    let Some(pattern) = caps.get(1).map(|m| m.as_str().trim()) else {
                        continue;
                    };
                    if pattern.is_empty() {
                        continue;
                    }
                    if condition_is_all {
                        if header_regex_all_seen.insert(pattern.to_string()) {
                            out.header_regex_all.push(pattern.to_string());
                        }
                    } else if header_regex_any_seen.insert(pattern.to_string()) {
                        out.header_regex_any.push(pattern.to_string());
                    }
                }
            }
        }
    }

    out
}

fn parse_header_pair(raw: &str) -> Option<(String, String)> {
    let (name_raw, value_raw) = raw.split_once(':')?;
    let name = name_raw.trim();
    let value = value_raw.trim();
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

fn contains_literal_regex(raw: &str) -> String {
    regex::escape(raw)
}

static DSL_STATUS_EQ_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bstatus_code\s*==\s*(\d{3})\b").expect("dsl status regex"));
static DSL_CONTAINS_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)contains\(\s*(?:tolower\(\s*)?(?:body|response\.body)\s*\)?\s*,\s*['"]([^'"]+)['"]\s*\)"#)
        .expect("dsl contains body regex")
});
static DSL_REGEX_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)regex\(\s*(?:tolower\(\s*)?(?:body|response\.body)\s*\)?\s*,\s*['"]([^'"]+)['"]\s*\)"#)
        .expect("dsl regex body regex")
});
static DSL_CONTAINS_HEADERS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)contains\(\s*(?:all_headers|header|response\.headers?)\s*,\s*['"]([^'"]+)['"]\s*\)"#,
    )
    .expect("dsl contains headers regex")
});
static DSL_REGEX_HEADERS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)regex\(\s*(?:all_headers|header|response\.headers?)\s*,\s*['"]([^'"]+)['"]\s*\)"#,
    )
    .expect("dsl regex headers regex")
});

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
