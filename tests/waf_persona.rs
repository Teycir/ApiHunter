use api_scanner::browser_persona::{sticky_headers_for_host, sticky_headers_for_url};

#[test]
fn sticky_persona_is_stable_for_same_host() {
    let uas = vec![
        "Mozilla/5.0 UA-A".to_string(),
        "Mozilla/5.0 UA-B".to_string(),
        "Mozilla/5.0 UA-C".to_string(),
    ];

    let first = sticky_headers_for_host("api.example.com", &uas);
    let second = sticky_headers_for_host("api.example.com", &uas);

    assert_eq!(first, second, "same host should keep same persona headers");
}

#[test]
fn sticky_persona_uses_provided_user_agent_pool() {
    let uas = vec!["Mozilla/5.0 UA-ONLY".to_string()];
    let headers = sticky_headers_for_url("https://api.example.com/v1", &uas);

    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ua, "Mozilla/5.0 UA-ONLY");
}

#[test]
fn sticky_persona_populates_browser_like_headers() {
    let uas = vec!["Mozilla/5.0 UA-A".to_string()];
    let headers = sticky_headers_for_url("https://api.example.com/v1", &uas);

    assert!(headers.get("accept").is_some());
    assert!(headers.get("accept-encoding").is_some());
    assert!(headers.get("accept-language").is_some());
    assert!(headers.get("sec-fetch-dest").is_some());
    assert!(headers.get("sec-fetch-mode").is_some());
    assert!(headers.get("sec-fetch-site").is_some());
}
