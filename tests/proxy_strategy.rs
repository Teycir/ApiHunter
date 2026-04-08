use api_scanner::proxy::{parse_proxy_file, parse_proxy_line, ProxyStrategy};

#[test]
fn parse_proxy_line_supports_host_port() {
    let parsed = parse_proxy_line("10.0.0.1:8080");
    assert_eq!(parsed.as_deref(), Some("http://10.0.0.1:8080"));
}

#[test]
fn parse_proxy_line_supports_host_port_user_pass() {
    let parsed = parse_proxy_line("proxy.example.com:3128:alice:s3cret");
    assert_eq!(
        parsed.as_deref(),
        Some("http://alice:s3cret@proxy.example.com:3128")
    );
}

#[test]
fn parse_proxy_line_supports_full_url() {
    let parsed = parse_proxy_line("socks5://proxy.example.com:1080");
    assert_eq!(parsed.as_deref(), Some("socks5://proxy.example.com:1080"));
}

#[test]
fn parse_proxy_file_ignores_comments_and_blanks() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proxies.txt");
    std::fs::write(
        &file,
        "# pool\n\nproxy1:8080:user1:pass1\nproxy2:3128\nhttps://proxy3:9443\n",
    )
    .unwrap();

    let proxies = parse_proxy_file(&file).unwrap();
    assert_eq!(proxies.len(), 3);
    assert_eq!(proxies[0], "http://user1:pass1@proxy1:8080");
    assert_eq!(proxies[1], "http://proxy2:3128");
    assert_eq!(proxies[2], "https://proxy3:9443");
}

#[test]
fn explicit_single_proxy_overrides_pool() {
    let strategy = ProxyStrategy::new(
        Some("http://single.proxy:8080".to_string()),
        vec![
            "http://pool1.proxy:8080".to_string(),
            "http://pool2.proxy:8080".to_string(),
        ],
    );

    assert_eq!(strategy.pool_size(), 0);
    assert_eq!(
        strategy.resolve_for_host("api.example.com").as_deref(),
        Some("http://single.proxy:8080")
    );
}

#[test]
fn pool_selection_is_stable_per_host() {
    let strategy = ProxyStrategy::new(
        None,
        vec![
            "http://pool1.proxy:8080".to_string(),
            "http://pool2.proxy:8080".to_string(),
            "http://pool3.proxy:8080".to_string(),
        ],
    );

    let first = strategy
        .resolve_for_host("api.example.com")
        .expect("pool proxy for host");
    let second = strategy
        .resolve_for_host("api.example.com")
        .expect("pool proxy for host");

    assert_eq!(first, second);
}

#[test]
fn pool_resolution_from_url_works() {
    let strategy = ProxyStrategy::new(None, vec!["http://pool1.proxy:8080".to_string()]);

    assert_eq!(
        strategy
            .resolve_for_url("https://service.example.com/v1/users")
            .as_deref(),
        Some("http://pool1.proxy:8080")
    );
}
