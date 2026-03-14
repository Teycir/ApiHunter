// src/http_client.rs
//
// Thin wrapper around `reqwest::Client` with WAF evasion, size capping,
// and convenience methods for the scanner modules.

use crate::{
    config::Config,
    error::{CapturedError, ScannerError, ScannerResult},
    waf::WafEvasion,
};
use dashmap::DashMap;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    Client, Method, Response,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::debug;
use url::Url;

/// Parsed, size-capped HTTP response.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub url: String,
}

#[allow(dead_code)]
impl HttpResponse {
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.get(&key.to_lowercase()).map(|s| s.as_str())
    }

    pub fn is_success(&self) -> bool {
        self.status < 400
    }

    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }
}

/// Maximum response body size in bytes (512 KB).
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// Thin wrapper around `reqwest::Client` with WAF evasion & size capping.
#[derive(Clone)]
pub struct HttpClient {
    inner: Client,
    waf_enabled: bool,
    delay_ms: u64,
    retries: u32,
    host_last_request: Arc<DashMap<String, tokio::time::Instant>>,
}

impl HttpClient {
    pub fn new(config: &Config) -> ScannerResult<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.politeness.timeout_secs))
            .danger_accept_invalid_certs(config.danger_accept_invalid_certs)
            .gzip(true)
            .deflate(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .tcp_keepalive(Duration::from_secs(30));

        let mut default_headers = HeaderMap::new();
        for (k, v) in &config.default_headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                default_headers.insert(name, value);
            }
        }

        if !config.cookies.is_empty() {
            let cookie_value = config
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");

            let key = HeaderName::from_static("cookie");
            if let Some(existing) = default_headers.get(&key).cloned() {
                let mut combined = existing.to_str().unwrap_or("").to_string();
                if !combined.is_empty() {
                    combined.push_str("; ");
                }
                combined.push_str(&cookie_value);
                if let Ok(value) = HeaderValue::from_str(&combined) {
                    default_headers.insert(key, value);
                }
            } else if let Ok(value) = HeaderValue::from_str(&cookie_value) {
                default_headers.insert(key, value);
            }
        }

        if !default_headers.is_empty() {
            builder = builder.default_headers(default_headers);
        }

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| ScannerError::Config(format!("Invalid proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let inner = builder
            .build()
            .map_err(|e| ScannerError::Config(format!("Client build failed: {e}")))?;

        Ok(Self {
            inner,
            waf_enabled: config.waf_evasion.enabled,
            delay_ms: config.politeness.delay_ms,
            retries: config.politeness.retries,
            host_last_request: Arc::new(DashMap::new()),
        })
    }

    // ------------------------------------------------------------------ //
    //  Core request entry point
    // ------------------------------------------------------------------ //

    /// Send a request, applying WAF evasion delays + rotating headers.
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        extra_headers: Option<HeaderMap>,
        body: Option<serde_json::Value>,
    ) -> Result<HttpResponse, CapturedError> {
        let attempts = self.retries + 1;
        let mut last_err: Option<CapturedError> = None;

        for attempt in 0..attempts {
            if attempt > 0 {
                let backoff = retry_backoff(attempt);
                tokio::time::sleep(backoff).await;
            }

            match self
                .send_once(
                    method.clone(),
                    url,
                    extra_headers.as_ref().cloned(),
                    body.as_ref().cloned(),
                )
                .await
            {
                Ok(resp) => {
                    if should_retry_status(resp.status) && attempt + 1 < attempts {
                        debug!(
                            "[{method} {url}] retrying due to status {} (attempt {}/{})",
                            resp.status,
                            attempt + 1,
                            attempts
                        );
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    debug!(
                        "[{method} {url}] attempt {}/{} failed: {}",
                        attempt + 1,
                        attempts,
                        e
                    );
                    last_err = Some(e);
                    if attempt + 1 == attempts {
                        break;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            CapturedError::from_str(
                "http::send",
                Some(url.to_string()),
                "request failed after retries",
            )
        }))
    }

    async fn send_once(
        &self,
        method: Method,
        url: &str,
        extra_headers: Option<HeaderMap>,
        body: Option<serde_json::Value>,
    ) -> Result<HttpResponse, CapturedError> {
        self.enforce_host_delay(url).await;

        // Random inter-request delay based on configured delay_ms.
        if self.waf_enabled && self.delay_ms > 0 {
            let min_secs = self.delay_ms as f64 / 1000.0;
            let max_secs = min_secs * 3.0; // jitter up to 3x
            WafEvasion::random_delay(min_secs, max_secs).await;
        }

        let mut req = self.inner.request(method.clone(), url);

        // Rotate UA + evasion headers on every request.
        if self.waf_enabled {
            req = req.headers(WafEvasion::evasion_headers());
        }

        if let Some(hdrs) = extra_headers {
            req = req.headers(hdrs);
        }

        if let Some(json_body) = body {
            req = req
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .json(&json_body);
        }

        let response = req.send().await.map_err(|e| {
            debug!("[{method} {url}] send error: {e}");
            CapturedError::new("http::send", Some(url.to_string()), &e)
        })?;

        self.read_response(response, url).await
    }

    async fn enforce_host_delay(&self, url: &str) {
        if self.delay_ms == 0 {
            return;
        }

        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return,
        };

        let host = match parsed.host_str() {
            Some(h) => h,
            None => return,
        };

        let mut key = host.to_string();
        if let Some(port) = parsed.port() {
            key.push_str(&format!(":{port}"));
        }

        let now = tokio::time::Instant::now();
        if let Some(last) = self.host_last_request.get(&key) {
            let elapsed = now.duration_since(*last);
            let min_gap = Duration::from_millis(self.delay_ms);
            if elapsed < min_gap {
                tokio::time::sleep(min_gap - elapsed).await;
            }
        }

        self.host_last_request.insert(key, tokio::time::Instant::now());
    }

    // ------------------------------------------------------------------ //
    //  Convenience wrappers
    // ------------------------------------------------------------------ //

    pub async fn get(&self, url: &str) -> Result<HttpResponse, CapturedError> {
        self.request(Method::GET, url, None, None).await
    }

    /// GET with extra request headers specified as `[(name, value)]` pairs.
    pub async fn get_with_headers(
        &self,
        url: &str,
        extra: &[(String, String)],
    ) -> Result<HttpResponse, CapturedError> {
        let mut map = HeaderMap::new();
        for (k, v) in extra {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                map.insert(name, value);
            }
        }
        self.request(Method::GET, url, Some(map), None).await
    }

    #[allow(dead_code)]
    pub async fn head(&self, url: &str) -> Result<HttpResponse, CapturedError> {
        self.request(Method::HEAD, url, None, None).await
    }

    pub async fn options(
        &self,
        url: &str,
        extra: Option<HeaderMap>,
    ) -> Result<HttpResponse, CapturedError> {
        self.request(Method::OPTIONS, url, extra, None).await
    }

    pub async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<HttpResponse, CapturedError> {
        self.request(Method::POST, url, None, Some(body.clone())).await
    }

    pub async fn method_probe(
        &self,
        method: &str,
        url: &str,
    ) -> Result<HttpResponse, CapturedError> {
        let m = Method::from_bytes(method.as_bytes()).map_err(|e| {
            CapturedError::from_str("http::method_probe", Some(url.to_string()), e.to_string())
        })?;
        self.request(m, url, None, None).await
    }

    // ------------------------------------------------------------------ //
    //  Response reading with size cap
    // ------------------------------------------------------------------ //

    async fn read_response(
        &self,
        response: Response,
        url: &str,
    ) -> Result<HttpResponse, CapturedError> {
        let status = response.status().as_u16();
        let final_url = response.url().to_string();

        // Flatten headers into lowercase map (last value wins for duplicates).
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        // Read body with size cap.
        let raw_bytes = response.bytes().await.map_err(|e| {
            CapturedError::new("http::read_body", Some(url.to_string()), &e)
        })?;

        let capped: &[u8] = if raw_bytes.len() > MAX_RESPONSE_BYTES {
            &raw_bytes[..MAX_RESPONSE_BYTES]
        } else {
            &raw_bytes
        };

        // Best-effort UTF-8 decode.
        let body = String::from_utf8_lossy(capped).into_owned();

        Ok(HttpResponse {
            status,
            headers,
            body,
            url: final_url,
        })
    }
}

fn should_retry_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

fn retry_backoff(attempt: u32) -> Duration {
    let shift = attempt.min(6);
    let exp = 1u64 << shift;
    Duration::from_millis(200 * exp)
}
