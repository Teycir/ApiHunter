use std::fs;

use assert_cmd::Command;
use tempfile::tempdir;

fn repo_path(rel: &str) -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel)
}

#[test]
fn import_nuclei_converts_get_template_into_apihunter_toml() {
    let tmp = tempdir().expect("tempdir");
    let out = tmp.path().join("cve-2022-24288.toml");

    Command::cargo_bin("template-tool")
        .expect("template-tool binary")
        .args([
            "import-nuclei",
            "--input",
            &repo_path("tests/fixtures/upstream_nuclei/CVE-2022-24288.yaml"),
            "--output",
            out.to_str().expect("out path"),
            "--check-suffix",
            "airflow-example-dag-params-rce-signal",
            "--context-hints",
            "/airflow,/admin,/dags,/code",
        ])
        .assert()
        .success();

    let toml_raw = fs::read_to_string(&out).expect("generated toml");
    let parsed: toml::Value = toml::from_str(&toml_raw).expect("parse generated toml");
    let tmpl = parsed
        .get("templates")
        .and_then(toml::Value::as_array)
        .and_then(|a| a.first())
        .expect("templates[0]");

    assert_eq!(
        tmpl.get("id").and_then(toml::Value::as_str),
        Some("CVE-2022-24288")
    );
    assert_eq!(
        tmpl.get("check").and_then(toml::Value::as_str),
        Some("cve/cve-2022-24288/airflow-example-dag-params-rce-signal")
    );
    assert_eq!(
        tmpl.get("method").and_then(toml::Value::as_str),
        Some("GET")
    );
    assert_eq!(
        tmpl.get("path").and_then(toml::Value::as_str),
        Some("/admin/airflow/code?root=&dag_id=example_passing_params_via_test_command")
    );

    let body_any = tmpl
        .get("body_contains_any")
        .and_then(toml::Value::as_array)
        .expect("body_contains_any");
    assert!(
        body_any.iter().any(|v| {
            v.as_str()
                .map(|s| s.contains("foo was passed in via Airflow CLI Test command"))
                .unwrap_or(false)
        }),
        "expected body matcher phrase in body_contains_any: {body_any:?}"
    );
}

#[test]
fn import_nuclei_extracts_status_matcher_when_present() {
    let tmp = tempdir().expect("tempdir");
    let out = tmp.path().join("cve-2021-29442.toml");

    Command::cargo_bin("template-tool")
        .expect("template-tool binary")
        .args([
            "import-nuclei",
            "--input",
            &repo_path("tests/fixtures/upstream_nuclei/CVE-2021-29442.yaml"),
            "--output",
            out.to_str().expect("out path"),
        ])
        .assert()
        .success();

    let toml_raw = fs::read_to_string(&out).expect("generated toml");
    let parsed: toml::Value = toml::from_str(&toml_raw).expect("parse generated toml");
    let tmpl = parsed
        .get("templates")
        .and_then(toml::Value::as_array)
        .and_then(|a| a.first())
        .expect("templates[0]");

    let status_any_of = tmpl
        .get("status_any_of")
        .and_then(toml::Value::as_array)
        .expect("status_any_of");
    assert!(
        status_any_of.iter().any(|v| v.as_integer() == Some(200)),
        "expected status_any_of to include 200: {status_any_of:?}"
    );
}

#[test]
fn import_nuclei_rejects_non_get_methods() {
    let tmp = tempdir().expect("tempdir");
    let in_yaml = tmp.path().join("post-template.yaml");
    let out = tmp.path().join("out.toml");

    fs::write(
        &in_yaml,
        r#"
id: CVE-2099-0001
info:
  name: Post-only probe
  severity: medium
http:
  - method: POST
    path:
      - "{{BaseURL}}/example"
    matchers:
      - type: status
        status: [200]
"#,
    )
    .expect("write fixture");

    Command::cargo_bin("template-tool")
        .expect("template-tool binary")
        .args([
            "import-nuclei",
            "--input",
            in_yaml.to_str().expect("in path"),
            "--output",
            out.to_str().expect("out path"),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Only GET method is supported by ApiHunter CVE templates",
        ));
}

#[test]
fn import_nuclei_selects_first_compatible_get_request_from_multi_request_template() {
    let tmp = tempdir().expect("tempdir");
    let in_yaml = tmp.path().join("multi-request.yaml");
    let out = tmp.path().join("out.toml");

    fs::write(
        &in_yaml,
        r#"
id: CVE-2099-0002
info:
  name: Multi request importer test
  severity: medium
http:
  - method: POST
    path:
      - "{{BaseURL}}/mutate"
    matchers:
      - type: status
        status: [200]
  - method: GET
    path:
      - "{{BaseURL}}/read"
    matchers:
      - type: status
        status: [200]
"#,
    )
    .expect("write fixture");

    Command::cargo_bin("template-tool")
        .expect("template-tool binary")
        .args([
            "import-nuclei",
            "--input",
            in_yaml.to_str().expect("in path"),
            "--output",
            out.to_str().expect("out path"),
        ])
        .assert()
        .success();

    let toml_raw = fs::read_to_string(&out).expect("generated toml");
    let parsed: toml::Value = toml::from_str(&toml_raw).expect("parse generated toml");
    let tmpl = parsed
        .get("templates")
        .and_then(toml::Value::as_array)
        .and_then(|a| a.first())
        .expect("templates[0]");

    assert_eq!(
        tmpl.get("method").and_then(toml::Value::as_str),
        Some("GET")
    );
    assert_eq!(
        tmpl.get("path").and_then(toml::Value::as_str),
        Some("/read")
    );
}

#[test]
fn import_nuclei_extracts_headers_from_raw_request_block() {
    let tmp = tempdir().expect("tempdir");
    let in_yaml = tmp.path().join("raw-headers.yaml");
    let out = tmp.path().join("out.toml");

    fs::write(
        &in_yaml,
        r#"
id: CVE-2099-0003
info:
  name: Raw header extraction test
  severity: low
http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        X-Api-Key: redteam
        User-Agent: custom-agent/1.0

    matchers:
      - type: status
        status: [200]
"#,
    )
    .expect("write fixture");

    Command::cargo_bin("template-tool")
        .expect("template-tool binary")
        .args([
            "import-nuclei",
            "--input",
            in_yaml.to_str().expect("in path"),
            "--output",
            out.to_str().expect("out path"),
        ])
        .assert()
        .success();

    let toml_raw = fs::read_to_string(&out).expect("generated toml");
    let parsed: toml::Value = toml::from_str(&toml_raw).expect("parse generated toml");
    let tmpl = parsed
        .get("templates")
        .and_then(toml::Value::as_array)
        .and_then(|a| a.first())
        .expect("templates[0]");

    let headers = tmpl
        .get("headers")
        .and_then(toml::Value::as_array)
        .expect("headers");

    let contains_pair = |name: &str, value: &str| {
        headers.iter().any(|h| {
            h.get("name").and_then(toml::Value::as_str) == Some(name)
                && h.get("value").and_then(toml::Value::as_str) == Some(value)
        })
    };

    assert!(contains_pair("X-Api-Key", "redteam"));
    assert!(contains_pair("User-Agent", "custom-agent/1.0"));
    assert!(
        !headers
            .iter()
            .any(|h| h.get("name").and_then(toml::Value::as_str) == Some("Host")),
        "Host header should not be imported from raw request blocks"
    );
}

#[test]
fn import_nuclei_translates_header_word_matchers_into_match_headers() {
    let tmp = tempdir().expect("tempdir");
    let in_yaml = tmp.path().join("header-matcher.yaml");
    let out = tmp.path().join("out.toml");

    fs::write(
        &in_yaml,
        r#"
id: CVE-2099-0004
info:
  name: Header matcher translation test
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status: [200]
      - type: word
        part: header
        words:
          - "Server: nginx"
          - "X-Frame-Options: DENY"
          - "no-colon-token"
"#,
    )
    .expect("write fixture");

    Command::cargo_bin("template-tool")
        .expect("template-tool binary")
        .args([
            "import-nuclei",
            "--input",
            in_yaml.to_str().expect("in path"),
            "--output",
            out.to_str().expect("out path"),
        ])
        .assert()
        .success();

    let toml_raw = fs::read_to_string(&out).expect("generated toml");
    let parsed: toml::Value = toml::from_str(&toml_raw).expect("parse generated toml");
    let tmpl = parsed
        .get("templates")
        .and_then(toml::Value::as_array)
        .and_then(|a| a.first())
        .expect("templates[0]");

    let match_headers = tmpl
        .get("match_headers")
        .and_then(toml::Value::as_array)
        .expect("match_headers");

    let contains_pair = |name: &str, value: &str| {
        match_headers.iter().any(|h| {
            h.get("name").and_then(toml::Value::as_str) == Some(name)
                && h.get("value").and_then(toml::Value::as_str) == Some(value)
        })
    };

    assert!(contains_pair("Server", "nginx"));
    assert!(contains_pair("X-Frame-Options", "DENY"));
    assert_eq!(match_headers.len(), 2);
}

#[test]
fn import_nuclei_translates_regex_and_dsl_matchers() {
    let tmp = tempdir().expect("tempdir");
    let in_yaml = tmp.path().join("regex-dsl.yaml");
    let out = tmp.path().join("out.toml");

    fs::write(
        &in_yaml,
        r#"
id: CVE-2099-0005
info:
  name: Regex and DSL translation test
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/regex"
    matchers:
      - type: regex
        part: body
        condition: and
        regex:
          - "(?i)admin\\s*=\\s*true"
      - type: regex
        part: all_headers
        regex:
          - "(?i)x-powered-by:\\s*express"
      - type: dsl
        condition: and
        dsl:
          - 'status_code == 200'
          - 'contains(body, "token")'
          - 'regex(body, "(?i)session_[a-z0-9]+")'
          - 'contains(all_headers, "Server: nginx")'
"#,
    )
    .expect("write fixture");

    Command::cargo_bin("template-tool")
        .expect("template-tool binary")
        .args([
            "import-nuclei",
            "--input",
            in_yaml.to_str().expect("in path"),
            "--output",
            out.to_str().expect("out path"),
        ])
        .assert()
        .success();

    let toml_raw = fs::read_to_string(&out).expect("generated toml");
    let parsed: toml::Value = toml::from_str(&toml_raw).expect("parse generated toml");
    let tmpl = parsed
        .get("templates")
        .and_then(toml::Value::as_array)
        .and_then(|a| a.first())
        .expect("templates[0]");

    assert!(tmpl
        .get("status_any_of")
        .and_then(toml::Value::as_array)
        .expect("status_any_of")
        .iter()
        .any(|v| v.as_integer() == Some(200)));
    assert!(tmpl
        .get("body_contains_all")
        .and_then(toml::Value::as_array)
        .expect("body_contains_all")
        .iter()
        .any(|v| v.as_str() == Some("token")));
    assert!(tmpl
        .get("body_regex_all")
        .and_then(toml::Value::as_array)
        .expect("body_regex_all")
        .iter()
        .any(|v| {
            v.as_str()
                .map(|s| s.contains("admin\\s*=\\s*true") || s.contains("session_[a-z0-9]+"))
                .unwrap_or(false)
        }));
    assert!(tmpl
        .get("header_regex_any")
        .and_then(toml::Value::as_array)
        .expect("header_regex_any")
        .iter()
        .any(|v| {
            v.as_str()
                .map(|s| s.contains("x-powered-by"))
                .unwrap_or(false)
        }));

    let match_headers = tmpl
        .get("match_headers")
        .and_then(toml::Value::as_array)
        .expect("match_headers");
    assert!(match_headers.iter().any(|h| {
        h.get("name").and_then(toml::Value::as_str) == Some("Server")
            && h.get("value").and_then(toml::Value::as_str) == Some("nginx")
    }));
}

#[test]
fn import_nuclei_emits_safe_preflight_chain_steps() {
    let tmp = tempdir().expect("tempdir");
    let in_yaml = tmp.path().join("chain.yaml");
    let out = tmp.path().join("out.toml");

    fs::write(
        &in_yaml,
        r#"
id: CVE-2099-0006
info:
  name: Request chain translation test
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/warmup"
  - method: POST
    path:
      - "{{BaseURL}}/mutate"
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status: [200]
"#,
    )
    .expect("write fixture");

    Command::cargo_bin("template-tool")
        .expect("template-tool binary")
        .args([
            "import-nuclei",
            "--input",
            in_yaml.to_str().expect("in path"),
            "--output",
            out.to_str().expect("out path"),
        ])
        .assert()
        .success();

    let toml_raw = fs::read_to_string(&out).expect("generated toml");
    let parsed: toml::Value = toml::from_str(&toml_raw).expect("parse generated toml");
    let tmpl = parsed
        .get("templates")
        .and_then(toml::Value::as_array)
        .and_then(|a| a.first())
        .expect("templates[0]");

    assert_eq!(
        tmpl.get("path").and_then(toml::Value::as_str),
        Some("/probe"),
        "main probe should be the GET request with matchers"
    );

    let preflight = tmpl
        .get("preflight_requests")
        .and_then(toml::Value::as_array)
        .expect("preflight_requests");
    assert_eq!(
        preflight.len(),
        1,
        "unsafe POST preflight should be skipped"
    );
    assert_eq!(
        preflight[0].get("path").and_then(toml::Value::as_str),
        Some("/warmup")
    );
    assert_eq!(
        preflight[0].get("method").and_then(toml::Value::as_str),
        Some("GET")
    );
}
