use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Invalid configuration: {0}")]
    Config(String),

    #[error("Task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("Response body too large (limit: {limit} bytes)")]
    ResponseTooLarge { limit: usize },

    #[error("Timeout after {0}s")]
    Timeout(u64),

    #[error("{0}")]
    Other(String),
}

/// A captured error event stored in the report
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapturedError {
    pub timestamp: String,
    pub context: String,
    pub url: Option<String>,
    pub error_type: String,
    pub message: String,
}

impl CapturedError {
    pub fn new(context: impl Into<String>, url: Option<String>, err: &dyn std::error::Error) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            context: context.into(),
            url,
            error_type: std::any::type_name_of_val(err).to_string(),
            message: err.to_string(),
        }
    }

    pub fn from_str(context: impl Into<String>, url: Option<String>, msg: impl Into<String>) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            context: context.into(),
            url,
            error_type: "String".to_string(),
            message: msg.into(),
        }
    }

    /// Construct a non-HTTP internal error (e.g. task panic).
    pub fn internal(msg: impl Into<String>) -> Self {
        CapturedError {
            url:     None,
            kind:    ErrorKind::Internal,
            message: msg.into(),
            ..Default::default()
        }
    }
}

pub type ScannerResult<T> = Result<T, ScannerError>;
