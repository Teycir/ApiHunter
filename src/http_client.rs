// src/http_client.rs
//
// Thin wrapper around `reqwest::Client` with WAF evasion, size capping,
// and convenience methods for the scanner modules.

use crate::{
    config::Config,
    error::{CapturedError, ScannerError, ScannerResult},
    waf::WafEvasion,
};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    Client, Method, Response,
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore, OwnedSemaphorePermit};
use tracing::debug;
use url::Url;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

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
    client_config: ClientConfig,
    per_host_clients: bool,
    clients: Arc<DashMap<String, Client>>,
    spec_cache: Arc<DashMap<String, String>>,
    waf_enabled: bool,
    delay_ms: u64,
    retries: u32,
    host_last_request: Arc<Mutex<HashMap<String, tokio::time::Instant>>>,
    session_store: Option<Arc<Mutex<SessionStore>>>,
    session_path: Option<PathBuf>,
    adaptive: Option<Arc<AdaptiveLimiter>>,
}

#[derive(Debug)]
struct AdaptiveLimiter {
    semaphore: Arc<Semaphore>,
    max: usize,
    min: usize,
    held: Mutex<Vec<OwnedSemaphorePermit>>,
    success_streak: std::sync::atomic::AtomicUsize,
}

impl AdaptiveLimiter {
    fn new(max: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max)),
            max,
            min: 1,
            held: Mutex::new(Vec::new()),
            success_streak: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    async fn acquire(&self) -> OwnedSemaphorePermit {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed")
    }

    async fn on_success(&self) {
        let streak = self.success_streak.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if streak >= 10 {
            self.success_streak.store(0, std::sync::atomic::Ordering::Relaxed);
            self.increase().await;
        }
    }

    async fn on_backoff(&self) {
        self.success_streak.store(0, std::sync::atomic::Ordering::Relaxed);
        self.decrease().await;
    }

    async fn decrease(&self) {
        let mut held = self.held.lock().await;
        let target = self.max.saturating_sub(held.len());
        if target <= self.min {
            return;
        }
        if let Ok(permit) = self.semaphore.clone().try_acquire_owned() {
            held.push(permit);
        }
    }

    async fn increase(&self) {
        let mut held = self.held.lock().await;
        if let Some(permit) = held.pop() {
            drop(permit);
        }
    }
}

#[derive(Debug, Clone)]
struct ClientConfig {
    timeout_secs: u64,
    danger_accept_invalid_certs: bool,
    default_headers: HeaderMap,
    proxy: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SessionFile {
    hosts: HashMap<String, HashMap<String, String>>,
}

type SessionStore = HashMap<String, HashMap<String, String>>;

impl HttpClient {
    pub fn new(config: &Config) -> ScannerResult<Self> {
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
            // apply later to builder
        }

        let client_config = ClientConfig {
            timeout_secs: config.politeness.timeout_secs,
            danger_accept_invalid_certs: config.danger_accept_invalid_certs,
            default_headers,
            proxy: config.proxy.clone(),
        };

        let inner = build_client(&client_config)?;

        let session_store = if let Some(path) = &config.session_file {
            if path.exists() {
                match load_session_file(path) {
                    Ok(store) => Some(Arc::new(Mutex::new(store))),
                    Err(e) => {
                        return Err(ScannerError::Config(format!(
                            "Failed to load session file: {e}"
                        )));
                    }
                }
            } else {
                Some(Arc::new(Mutex::new(HashMap::new())))
            }
        } else {
            None
        };

        Ok(Self {
            inner,
            client_config,
            per_host_clients: config.per_host_clients,
            clients: Arc::new(DashMap::new()),
            spec_cache: Arc::new(DashMap::new()),
            waf_enabled: config.waf_evasion.enabled,
            delay_ms: config.politeness.delay_ms,
            retries: config.politeness.retries,
            host_last_request: Arc::new(Mutex::new(HashMap::new())),
            session_store,
            session_path: config.session_file.clone(),
            adaptive: if config.adaptive_concurrency {
                Some(Arc::new(AdaptiveLimiter::new(config.concurrency.max(1))))
            } else {
                None
            },
        })
    }

    pub fn cache_spec(&self, url: &str, body: &str) {
        self.spec_cache.insert(url.to_string(), body.to_string());
    }

    pub fn get_cached_spec(&self, url: &str) -> Option<String> {
        self.spec_cache.get(url).map(|v| v.value().clone())
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
        let _adaptive_permit = if let Some(adaptive) = &self.adaptive {
            Some(adaptive.acquire().await)
        } else {
            None
        };

        self.enforce_host_delay(url).await;

        // Random inter-request delay based on configured delay_ms.
        if self.waf_enabled && self.delay_ms > 0 {
            let min_secs = self.delay_ms as f64 / 1000.0;
            let max_secs = min_secs * 3.0; // jitter up to 3x
            WafEvasion::random_delay(min_secs, max_secs).await;
        }

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
                    if let Some(adaptive) = &self.adaptive {
                        if should_retry_status(resp.status) {
                            adaptive.on_backoff().await;
                        } else {
                            adaptive.on_success().await;
                        }
                    }
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
                    if let Some(adaptive) = &self.adaptive {
                        adaptive.on_backoff().await;
                    }
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
        let client = self.client_for_url(url).map_err(|e| {
            CapturedError::from_str("http::client", Some(url.to_string()), e)
        })?;
        let mut req = client.request(method.clone(), url);

        // Rotate UA + evasion headers on every request.
        if self.waf_enabled {
            req = req.headers(WafEvasion::evasion_headers());
        }

        let mut combined_headers = HeaderMap::new();

        if let Some(hdrs) = extra_headers {
            combined_headers.extend(hdrs);
        }

        if let Some(cookie) = self.cookie_header_for(url).await {
            let key = HeaderName::from_static("cookie");
            let merged = if let Some(existing) = combined_headers.get(&key) {
                let mut combined = existing.to_str().unwrap_or("").to_string();
                if !combined.is_empty() {
                    combined.push_str("; ");
                }
                combined.push_str(&cookie);
                combined
            } else {
                cookie
            };
            if let Ok(value) = HeaderValue::from_str(&merged) {
                combined_headers.insert(key, value);
            }
        }

        if !combined_headers.is_empty() {
            req = req.headers(combined_headers);
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

        let min_gap = Duration::from_millis(self.delay_ms);
        let now = tokio::time::Instant::now();

        // Reserve the next allowed time per host to prevent concurrent TOCTOU races.
        let sleep_for = {
            let mut map = self.host_last_request.lock().await;
            let next_allowed = match map.get(&key) {
                Some(last) => {
                    let candidate = *last + min_gap;
                    if candidate > now { candidate } else { now }
                }
                None => now,
            };
            map.insert(key, next_allowed);
            if next_allowed > now {
                next_allowed - now
            } else {
                Duration::from_millis(0)
            }
        };

        if !sleep_for.is_zero() {
            tokio::time::sleep(sleep_for).await;
        }
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

        let set_cookies: Vec<String> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect();

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

        if let Some(store) = &self.session_store {
            if let Err(e) = self.update_session_from_set_cookie(&set_cookies, &final_url, store).await {
                debug!("[session] update error for {final_url}: {e}");
            }
        }

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

    fn client_for_url(&self, url: &str) -> Result<Client, String> {
        if !self.per_host_clients {
            return Ok(self.inner.clone());
        }

        let host = Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        if let Some(client) = self.clients.get(&host) {
            return Ok(client.value().clone());
        }

        let client = build_client(&self.client_config)
            .map_err(|e| format!("per-host client build failed: {e}"))?;
        self.clients.insert(host, client.clone());
        Ok(client)
    }

    async fn cookie_header_for(&self, url: &str) -> Option<String> {
        let store = self.session_store.as_ref()?;
        let host = Url::parse(url).ok().and_then(|u| u.host_str().map(|h| h.to_string()))?;
        let map = store.lock().await;
        let cookies = map.get(&host)?;
        if cookies.is_empty() {
            return None;
        }
        let value = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        Some(value)
    }

    async fn update_session_from_set_cookie(
        &self,
        set_cookies: &[String],
        url: &str,
        store: &Arc<Mutex<SessionStore>>,
    ) -> Result<(), String> {
        let host = Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .ok_or_else(|| "invalid response url".to_string())?;

        if set_cookies.is_empty() {
            return Ok(());
        }

        let mut map = store.lock().await;
        let entry = map.entry(host).or_insert_with(HashMap::new);

        for raw in set_cookies {
            let part = raw.split(';').next().unwrap_or("").trim();
            let mut kv = part.splitn(2, '=');
            let name = kv.next().unwrap_or("").trim();
            let value = kv.next().unwrap_or("").trim();
            if !name.is_empty() && !value.is_empty() {
                entry.insert(name.to_string(), value.to_string());
            }
        }
        Ok(())
    }

    pub async fn save_session(&self) -> ScannerResult<()> {
        let Some(path) = &self.session_path else { return Ok(()); };
        let Some(store) = &self.session_store else { return Ok(()); };

        let map = store.lock().await;
        let doc = SessionFile { hosts: map.clone() };
        let json = serde_json::to_string_pretty(&doc)
            .map_err(|e| ScannerError::Config(format!("Session serialise failed: {e}")))?;
        std::fs::write(path, json)
            .map_err(|e| ScannerError::Config(format!("Session write failed: {e}")))?;
        Ok(())
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

fn build_client(cfg: &ClientConfig) -> ScannerResult<Client> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs))
        .danger_accept_invalid_certs(cfg.danger_accept_invalid_certs)
        .gzip(true)
        .deflate(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .tcp_keepalive(Duration::from_secs(30));

    if !cfg.default_headers.is_empty() {
        builder = builder.default_headers(cfg.default_headers.clone());
    }

    if let Some(proxy_url) = &cfg.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ScannerError::Config(format!("Invalid proxy: {e}")))?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|e| ScannerError::Config(format!("Client build failed: {e}")))
}

fn load_session_file(path: &PathBuf) -> Result<SessionStore, ScannerError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ScannerError::Config(format!("Session read failed: {e}")))?;
    let doc: SessionFile = serde_json::from_str(&content)
        .map_err(|e| ScannerError::Config(format!("Session parse failed: {e}")))?;
    Ok(doc.hosts)
}
