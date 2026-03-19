use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

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

#[test]
fn accessibility_filter_uses_configured_proxy() {
    let tmp = tempdir().expect("tempdir");
    let urls = tmp.path().join("urls.txt");
    fs::write(&urls, "http://proxy-required.invalid/seed\n").expect("write urls");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy listener");
    let proxy_addr = listener.local_addr().expect("proxy local addr");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy listener");

    let proxy_handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    );
                    let _ = stream.flush();
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });

    Command::cargo_bin("apihunter")
        .expect("apihunter binary")
        .args([
            "--urls",
            urls.to_str().expect("urls path"),
            "--proxy",
            &format!("http://{proxy_addr}"),
            "--filter-timeout",
            "1",
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
        ])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Targets: 1").and(
                predicate::str::contains("No accessible URLs remaining after filtering").not(),
            ),
        );

    proxy_handle.join().expect("proxy thread join");
}
