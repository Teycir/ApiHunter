use crate::{
    config::Config,
    error::{CapturedError, ScannerError, ScannerResult},
    waf::WafEvasion,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client, Method, Response,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::debug;

/// Parsed, size-capped HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub url: String,
}

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

/// Thin wrapper around `reqwest::Client` with WAF evasion & size capping
#[derive(Clone)]
pub struct HttpClient {
    inner: Client,
    config: Arc<Config>,
}

impl HttpClient {
    pub fn new(config: Arc<Config>) -> ScannerResult<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .danger_accept_invalid_certs(config.insecure)
            .gzip(true)
            .deflate(true)
            .brotli(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .tcp_keepalive(Duration::from_secs(30));

        if config.waf_evasion_enabled() {
            builder = builder.default_headers(WafEvasion::evasion_headers());
        }

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| ScannerError::Config(format!("Invalid proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let inner = builder
            .build()
            .map_err(|e| ScannerError::Config(format!("Client build failed: {e}")))?;

        Ok(Self { inner, config })
    }

    // ------------------------------------------------------------------ //
    //  Core request entry point
    // ------------------------------------------------------------------ //

    /// Send a request, applying WAF evasion delays + rotating headers.
    /// Always returns `Ok(HttpResponse)` or `Err(CapturedError)` — never panics.
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        extra_headers: Option<HeaderMap>,
        body: Option<serde_json::Value>,
    ) -> Result<HttpResponse, CapturedError> {
        // Random inter-request delay
        if self.config.waf_evasion_enabled() {
            WafEvasion::random_delay(self.config.min_delay, self.config.max_delay).await;
        }

        let mut req = self.inner.request(method.clone(), url);

        // Rotate UA + evasion headers on every request
        if self.config.waf_evasion_enabled() {
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

    // ------------------------------------------------------------------ //
    //  Convenience wrappers
    // ------------------------------------------------------------------ //

    pub async fn get(&self, url: &str) -> Result<HttpResponse, CapturedError> {
        self.request(Method::GET, url, None, None).await
    }

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
        body: serde_json::Value,
    ) -> Result<HttpResponse, CapturedError> {
        self.request(Method::POST, url, None, Some(body)).await
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

        // Flatten headers into lowercase map (last value wins for duplicates)
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

        // Stream body with size cap
        let max = self.config.max_response_bytes();
        let raw_bytes = response.bytes().await.map_err(|e| {
            CapturedError::new("http::read_body", Some(url.to_string()), &e)
        })?;

        let capped: &[u8] = if raw_bytes.len() > max {
            &raw_bytes[..max]
        } else {
            &raw_bytes
        };

        // Best-effort UTF-8 decode
        let body = String::from_utf8_lossy(capped).into_owned();

        Ok(HttpResponse {
            status,
            headers,
            body,
            url: final_url,
        })
    }
}
