use crate::{
    config::Config,
    error::{CapturedError, ScannerError, ScannerResult},
    waf::WafEvasion,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client, Method, Response, StatusCode,
};
use std::{sync::Arc, time::Duration};
use tracing::{debug, warn};

/// Thin wrapper around a `reqwest::Client` that applies WAF evasion
/// and response-size limiting on every request.
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
            .tcp_keepalive(Duration::from_secs(30))
            .connection_verbose(false);

        if config.waf_evasion_enabled() {
            builder = builder.default_headers(WafEvasion::evasion_headers());
        }

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| ScannerError::Config(format!("Invalid proxy URL: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let inner = builder
            .build()
            .map_err(|e| ScannerError::Config(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self { inner, config })
    }

    /// Core request method — handles delays, header merging, size cap
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        extra_headers: Option<HeaderMap>,
        body: Option<serde_json::Value>,
    ) -> Result<HttpResponse, CapturedError> {
        // WAF delay
        if self.config.waf_evasion_enabled() {
            WafEvasion::random_delay(self.config.min_delay, self.config.max_delay).await;
        }

        let mut req = self.inner.request(method.clone(), url);

        // Per-request header overrides (rotate UA each time)
        if self.config.waf_evasion_enabled() {
            req = req.headers(WafEvasion::evasion_headers());
        }
        if let Some(hdrs) = extra_headers {
            req = req.headers(hdrs);
        }

        if let Some(json) = body {
            req = req
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .json(&json);
        }

        let response = req.send().await.map_err(|e| {
            debug!("Request error [{method} {url}]: {e}");
            CapturedError::new("http_client::request", Some(url.to_string()), &e)
        })?;

        self.read_response(response, url).await
    }
