use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn auth_flow_path_is_validated_before_runtime() {
    let tmp = tempdir().expect("tempdir");
    let missing_flow = tmp.path().join("missing-auth-flow.json");

    Command::cargo_bin("apihunter")
        .expect("apihunter binary")
        .args([
            "--stdin",
            "--auth-flow",
            missing_flow.to_str().expect("missing flow path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--auth-flow file not found"));
}

#[test]
fn empty_cookie_values_are_accepted() {
    let tmp = tempdir().expect("tempdir");
    let urls = tmp.path().join("urls.txt");
    fs::write(&urls, "http://example.com\n").expect("write urls");

    Command::cargo_bin("apihunter")
        .expect("apihunter binary")
        .args([
            "--urls",
            urls.to_str().expect("urls path"),
            "--no-filter",
            "--no-discovery",
            "--no-cors",
            "--no-csp",
            "--no-graphql",
            "--no-api-security",
            "--no-jwt",
            "--no-openapi",
            "--no-mass-assignment",
            "--no-oauth-oidc",
            "--no-rate-limit",
            "--no-cve-templates",
            "--no-websocket",
            "--cookies",
            "session=",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Invalid cookie format").not());
}
