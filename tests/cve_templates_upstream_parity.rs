use std::{fs, path::PathBuf};

use serde::Deserialize;
use serde_yml::Value;

#[derive(Debug, Deserialize)]
struct TemplateFile {
    templates: Vec<LocalTemplate>,
}

#[derive(Debug, Deserialize)]
struct LocalTemplate {
    id: String,
    source: String,
    #[serde(default)]
    body_contains_any: Vec<String>,
    #[serde(default)]
    body_contains_all: Vec<String>,
}

fn repo_file(path: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push(path);
    p
}

fn read_local_template(path: &str) -> LocalTemplate {
    let p = repo_file(path);
    let raw =
        fs::read_to_string(&p).unwrap_or_else(|e| panic!("failed to read '{}': {e}", p.display()));
    let parsed: TemplateFile =
        toml::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse '{}': {e}", p.display()));
    parsed
        .templates
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no template entries in '{}'", p.display()))
}

fn read_upstream_yaml(path: &str) -> Value {
    let p = repo_file(path);
    let raw =
        fs::read_to_string(&p).unwrap_or_else(|e| panic!("failed to read '{}': {e}", p.display()));
    serde_yml::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse yaml '{}': {e}", p.display()))
}

fn read_fixture(path: &str) -> String {
    let p = repo_file(path);
    let bytes = fs::read(&p).unwrap_or_else(|e| panic!("failed to read '{}': {e}", p.display()));
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn local_templates_reference_real_upstream_nuclei_snapshots() {
    let cases = [
        (
            "assets/cve_templates/cve-2022-22947.toml",
            "tests/fixtures/upstream_nuclei/CVE-2022-22947.yaml",
            "CVE-2022-22947",
        ),
        (
            "assets/cve_templates/cve-2021-29441.toml",
            "tests/fixtures/upstream_nuclei/CVE-2021-29441.yaml",
            "CVE-2021-29441",
        ),
        (
            "assets/cve_templates/cve-2021-29442.toml",
            "tests/fixtures/upstream_nuclei/CVE-2021-29442.yaml",
            "CVE-2021-29442",
        ),
        (
            "assets/cve_templates/cve-2020-13945.toml",
            "tests/fixtures/upstream_nuclei/CVE-2020-13945.yaml",
            "CVE-2020-13945",
        ),
        (
            "assets/cve_templates/cve-2020-3452.toml",
            "tests/fixtures/upstream_nuclei/CVE-2020-3452.yaml",
            "CVE-2020-3452",
        ),
        (
            "assets/cve_templates/cve-2021-45232.toml",
            "tests/fixtures/upstream_nuclei/CVE-2021-45232.yaml",
            "CVE-2021-45232",
        ),
        (
            "assets/cve_templates/cve-2022-24288.toml",
            "tests/fixtures/upstream_nuclei/CVE-2022-24288.yaml",
            "CVE-2022-24288",
        ),
    ];

    for (local_path, upstream_path, cve_id) in cases {
        let local = read_local_template(local_path);
        let upstream = read_upstream_yaml(upstream_path);

        assert_eq!(
            local.id, cve_id,
            "local template id mismatch in '{local_path}'"
        );
        assert!(
            local.source.contains(cve_id),
            "local source should reference cve id in '{local_path}'"
        );

        let upstream_id = upstream
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            upstream_id, cve_id,
            "upstream fixture id mismatch in '{upstream_path}'"
        );
    }
}

#[test]
fn body_match_indicators_align_with_real_captured_payloads() {
    let cases = [
        (
            "assets/cve_templates/cve-2022-22947.toml",
            "tests/fixtures/real_cve_payloads/cve-2022-22947-body.json",
        ),
        (
            "assets/cve_templates/cve-2021-29441.toml",
            "tests/fixtures/real_cve_payloads/cve-2021-29441-bypass-body.json",
        ),
        (
            "assets/cve_templates/cve-2021-29442.toml",
            "tests/fixtures/real_cve_payloads/cve-2021-29442-body.json",
        ),
        (
            "assets/cve_templates/cve-2020-13945.toml",
            "tests/fixtures/real_cve_payloads/cve-2020-13945-body.json",
        ),
        (
            "assets/cve_templates/cve-2021-45232.toml",
            "tests/fixtures/real_cve_payloads/cve-2021-45232-body.json",
        ),
        (
            "assets/cve_templates/cve-2022-24288.toml",
            "tests/fixtures/real_cve_payloads/cve-2022-24288-body.py",
        ),
    ];

    for (template_path, fixture_path) in cases {
        let local = read_local_template(template_path);
        let body_l = read_fixture(fixture_path).to_ascii_lowercase();

        if !local.body_contains_all.is_empty() {
            assert!(
                local
                    .body_contains_all
                    .iter()
                    .all(|term| body_l.contains(&term.to_ascii_lowercase())),
                "all-match terms should exist in real fixture body: template='{template_path}', fixture='{fixture_path}'"
            );
        }

        if !local.body_contains_any.is_empty() {
            assert!(
                local
                    .body_contains_any
                    .iter()
                    .any(|term| body_l.contains(&term.to_ascii_lowercase())),
                "any-match terms should intersect real fixture body: template='{template_path}', fixture='{fixture_path}'"
            );
        }
    }
}
