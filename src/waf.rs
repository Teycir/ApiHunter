use rand::seq::SliceRandom;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::sync::OnceLock;
use std::time::Duration;

/// Embedded fallback pool used if the asset file is empty/invalid.
const EMBEDDED_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
];

static USER_AGENT_POOL: OnceLock<Vec<String>> = OnceLock::new();

pub struct WafEvasion;

impl WafEvasion {
    /// Return the runtime User-Agent pool loaded from assets with fallback.
    pub fn user_agent_pool() -> Vec<String> {
        USER_AGENT_POOL.get_or_init(load_user_agent_pool).clone()
    }

    /// Pick a random User-Agent
    pub fn random_user_agent() -> String {
        let mut rng = rand::thread_rng();
        let pool = USER_AGENT_POOL.get_or_init(load_user_agent_pool);
        pool.choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| EMBEDDED_USER_AGENTS[0].to_string())
    }

    /// Build a realistic-looking HeaderMap for WAF evasion
    pub fn evasion_headers() -> HeaderMap {
        let mut map = HeaderMap::new();
        let ua = Self::random_user_agent();

        if let Ok(value) = HeaderValue::from_str(&ua) {
            map.insert(HeaderName::from_static("user-agent"), value);
        }

        let pairs: &[(&str, &str)] = &[
            (
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            ),
            ("accept-language", "en-US,en;q=0.5"),
            ("accept-encoding", "gzip, deflate, br"),
            ("dnt", "1"),
            ("connection", "keep-alive"),
            ("upgrade-insecure-requests", "1"),
            ("sec-fetch-dest", "document"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-site", "none"),
            ("cache-control", "max-age=0"),
        ];

        for (k, v) in pairs {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                map.insert(name, value);
            }
        }

        map
    }

    /// Async random sleep between [min, max] seconds
    pub async fn random_delay(min_secs: f64, max_secs: f64) {
        let delay = {
            let mut rng = rand::thread_rng();
            rng.gen_range(min_secs..=max_secs)
        };
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
    }
}

fn load_user_agent_pool() -> Vec<String> {
    let raw = include_str!("../assets/user_agents.txt");
    let mut entries: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect();

    if entries.is_empty() {
        entries = EMBEDDED_USER_AGENTS
            .iter()
            .map(|ua| ua.to_string())
            .collect();
    }

    entries
}
