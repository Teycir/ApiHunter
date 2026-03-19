use std::collections::HashMap;

use serde_json::Value;

use crate::http_client::HttpResponse;

pub fn get_content_type(headers: &HashMap<String, String>) -> String {
    headers
        .get("content-type")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn is_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();

    media_type
        .as_bytes()
        .windows(4)
        .any(|window| window.eq_ignore_ascii_case(b"json"))
}

pub fn is_html_content_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower.contains("text/html") || lower.contains("application/xhtml")
}

pub fn is_json_response(headers: &HashMap<String, String>, body: &str) -> bool {
    let ct = get_content_type(headers);
    is_json_content_type(&ct) || serde_json::from_str::<Value>(body).is_ok()
}

pub fn parse_json_body(body: &str, content_type: Option<&str>) -> Option<Value> {
    let parsed = serde_json::from_str::<Value>(body).ok();
    let is_json = content_type.map(is_json_content_type).unwrap_or(false);

    if is_json || parsed.is_some() {
        parsed
    } else {
        None
    }
}

pub fn parse_json_response(resp: &HttpResponse) -> Option<Value> {
    parse_json_body(
        &resp.body,
        resp.headers.get("content-type").map(|s| s.as_str()),
    )
}
