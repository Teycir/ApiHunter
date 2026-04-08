use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use url::Url;

const FALLBACK_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";

const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en-US,en;q=0.7,fr;q=0.3",
];

const FETCH_DEST: &[&str] = &["empty", "document"];
const FETCH_MODE: &[&str] = &["cors", "navigate"];
const FETCH_SITE: &[&str] = &["same-origin", "same-site", "none"];

/// Build deterministic browser-like headers per host.
///
/// This keeps a stable persona for a host while still allowing different
/// hosts to present different personas.
pub fn sticky_headers_for_url(url: &str, user_agents: &[String]) -> HeaderMap {
    let host = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    sticky_headers_for_host(&host, user_agents)
}

/// Build deterministic browser-like headers for a host key.
pub fn sticky_headers_for_host(host: &str, user_agents: &[String]) -> HeaderMap {
    let mut map = HeaderMap::new();

    let ua = pick_user_agent(host, user_agents);
    insert_header(&mut map, "user-agent", ua.as_str());

    insert_header(&mut map, "accept", "application/json,text/plain,*/*;q=0.9");
    insert_header(&mut map, "accept-encoding", "gzip, deflate, br");
    insert_header(&mut map, "connection", "keep-alive");
    insert_header(&mut map, "cache-control", "no-cache");
    insert_header(&mut map, "pragma", "no-cache");

    insert_header(
        &mut map,
        "accept-language",
        pick_str(host, "lang", ACCEPT_LANGUAGES),
    );
    insert_header(
        &mut map,
        "sec-fetch-dest",
        pick_str(host, "dest", FETCH_DEST),
    );
    insert_header(
        &mut map,
        "sec-fetch-mode",
        pick_str(host, "mode", FETCH_MODE),
    );
    insert_header(
        &mut map,
        "sec-fetch-site",
        pick_str(host, "site", FETCH_SITE),
    );

    if pick_bool(host, "dnt", 70) {
        insert_header(&mut map, "dnt", "1");
    }

    map
}

fn pick_user_agent(host: &str, user_agents: &[String]) -> String {
    if user_agents.is_empty() {
        return FALLBACK_UA.to_string();
    }
    let idx = hashed_index(host, "ua", user_agents.len());
    user_agents
        .get(idx)
        .cloned()
        .unwrap_or_else(|| FALLBACK_UA.to_string())
}

fn pick_str<'a>(host: &str, salt: &str, values: &'a [&'a str]) -> &'a str {
    let idx = hashed_index(host, salt, values.len());
    values[idx]
}

fn pick_bool(host: &str, salt: &str, threshold_pct: u8) -> bool {
    let score = (hash_u64(host, salt) % 100) as u8;
    score < threshold_pct
}

fn hashed_index(host: &str, salt: &str, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    (hash_u64(host, salt) as usize) % len
}

fn hash_u64(host: &str, salt: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    salt.hash(&mut hasher);
    hasher.finish()
}

fn insert_header(map: &mut HeaderMap, key: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(key.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        map.insert(name, value);
    }
}
