// tests/waf_user_agents.rs
//
// Validate runtime User-Agent pool behavior for WAF evasion.

use std::collections::HashSet;

use api_scanner::waf::WafEvasion;

#[test]
fn user_agent_pool_is_non_empty_and_browser_like() {
    let pool = WafEvasion::user_agent_pool();
    assert!(
        !pool.is_empty(),
        "runtime User-Agent pool should not be empty"
    );
    for ua in &pool {
        assert!(
            ua.starts_with("Mozilla/"),
            "User-Agent should look browser-like: {ua}"
        );
    }
}

#[test]
fn random_user_agent_comes_from_runtime_pool() {
    let pool = WafEvasion::user_agent_pool();
    let set: HashSet<_> = pool.into_iter().collect();
    assert!(!set.is_empty(), "runtime pool must not be empty");

    for _ in 0..20 {
        let ua = WafEvasion::random_user_agent();
        assert!(set.contains(&ua), "random UA must come from runtime pool");
    }
}

#[test]
fn evasion_headers_include_user_agent() {
    let headers = WafEvasion::evasion_headers();
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(!ua.is_empty(), "evasion headers must include user-agent");
}
