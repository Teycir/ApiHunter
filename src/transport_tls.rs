use reqwest::{tls::Version, ClientBuilder};

/// Optional transport TLS profile.
///
/// Default (`System`) preserves current behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TlsProfile {
    /// Keep reqwest/rustls defaults.
    #[default]
    System,
    /// Browser-like modern range (TLS 1.2-1.3).
    Modern,
    /// Strict TLS 1.3 only.
    Tls13Only,
}

/// Apply a TLS profile to a reqwest client builder.
pub fn apply_tls_profile(builder: ClientBuilder, profile: TlsProfile) -> ClientBuilder {
    match profile {
        TlsProfile::System => builder,
        TlsProfile::Modern => builder
            .min_tls_version(Version::TLS_1_2)
            .max_tls_version(Version::TLS_1_3)
            .tls_sni(true),
        TlsProfile::Tls13Only => builder
            .min_tls_version(Version::TLS_1_3)
            .max_tls_version(Version::TLS_1_3)
            .tls_sni(true),
    }
}
