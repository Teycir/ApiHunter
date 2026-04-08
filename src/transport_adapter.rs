use crate::{
    error::{ScannerError, ScannerResult},
    transport_tls::{apply_tls_profile, TlsProfile},
};
use reqwest::{header::HeaderMap, Client};
use std::time::Duration;

/// Supported transport backends.
///
/// Additive by design: `Reqwest` remains default and preserves current behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransportBackend {
    #[default]
    Reqwest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectMode {
    Limited(u32),
    None,
}

#[derive(Debug, Clone)]
pub struct TransportClientOptions {
    pub timeout_secs: u64,
    pub connect_timeout_secs: Option<u64>,
    pub tcp_keepalive_secs: Option<u64>,
    pub danger_accept_invalid_certs: bool,
    pub default_headers: HeaderMap,
    pub proxy_url: Option<String>,
    pub tls_profile: TlsProfile,
    pub redirect_mode: RedirectMode,
}

pub trait TransportAdapter: Send + Sync {
    fn build_client(&self, options: &TransportClientOptions) -> ScannerResult<Client>;
}

#[derive(Debug, Default)]
pub struct ReqwestTransportAdapter;

impl TransportAdapter for ReqwestTransportAdapter {
    fn build_client(&self, options: &TransportClientOptions) -> ScannerResult<Client> {
        let redirect = match options.redirect_mode {
            RedirectMode::Limited(n) => reqwest::redirect::Policy::limited(n as usize),
            RedirectMode::None => reqwest::redirect::Policy::none(),
        };

        let mut builder = Client::builder()
            .timeout(Duration::from_secs(options.timeout_secs))
            .danger_accept_invalid_certs(options.danger_accept_invalid_certs)
            .gzip(true)
            .deflate(true)
            .redirect(redirect);

        if let Some(connect_timeout_secs) = options.connect_timeout_secs {
            builder = builder.connect_timeout(Duration::from_secs(connect_timeout_secs));
        }
        if let Some(tcp_keepalive_secs) = options.tcp_keepalive_secs {
            builder = builder.tcp_keepalive(Duration::from_secs(tcp_keepalive_secs));
        }

        builder = apply_tls_profile(builder, options.tls_profile);

        if !options.default_headers.is_empty() {
            builder = builder.default_headers(options.default_headers.clone());
        }

        if let Some(proxy_url) = &options.proxy_url {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| ScannerError::Config(format!("Invalid proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }

        builder
            .build()
            .map_err(|e| ScannerError::Config(format!("Client build failed: {e}")))
    }
}

pub fn build_client(
    backend: TransportBackend,
    options: &TransportClientOptions,
) -> ScannerResult<Client> {
    match backend {
        TransportBackend::Reqwest => ReqwestTransportAdapter.build_client(options),
    }
}
