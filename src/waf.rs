use rand::seq::SliceRandom;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::time::Duration;

/// Static pool of realistic browser User-Agent strings
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
];

pub struct WafEvasion;

impl WafEvasion {
    /// Pick a random User-Agent
    pub fn random_user_agent() -> &'static str {
        let mut rng = rand::thread_rng();
        USER_AGENTS.choose(&mut rng).unwrap_or(&USER_AGENTS[0])
    }

    /// Build a realistic-looking HeaderMap for WAF evasion
    pub fn evasion_headers() -> HeaderMap {
        let mut map = HeaderMap::new();
        let ua = Self::random_user_agent();

        let pairs: &[(&str, &str)] = &[
            ("user-agent", ua),
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
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
