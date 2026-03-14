use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{error::CapturedError, http_client::HttpClient};

// Fallback: extract "/something" strings from raw text when JSON parse fails
static PATH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["'](/[a-zA-Z0-9_/\-\.\{\}]{2,120})["']"#).unwrap());

// --------------------------------------------------------------------------
// Minimal OpenAPI / Swagger schema types (v2 + v3)
// --------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OpenApiV3 {
    paths: Option<std::collections::HashMap<String, serde_json::Value>>,
    servers: Option<Vec<ServerObject>>,
}

#[derive(Debug, Deserialize)]
struct ServerObject {
    url: String,
}

#[derive(Debug, Deserialize)]
struct SwaggerV2 {
    paths: Option<std::collections::HashMap<String, serde_json::Value>>,
    #[
