use wiremock::ResponseTemplate;

use api_scanner::reports::{Finding, Severity};

pub fn mock_json_response(status: u16, body: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("Content-Type", "application/json")
        .set_body_string(body)
}

pub fn assert_finding_exists(findings: &[Finding], check: &str, severity: Severity) {
    assert!(
        findings
            .iter()
            .any(|f| f.check == check && f.severity == severity),
        "expected finding {check} with severity {severity:?}, got: {findings:#?}"
    );
}
