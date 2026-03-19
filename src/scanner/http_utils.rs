use serde_json::Value;

use crate::http_client::HttpResponse;

pub fn parse_json_response(resp: &HttpResponse) -> Option<Value> {
    parse_json_body(
        &resp.body,
        resp.headers.get("content-type").map(|s| s.as_str()),
    )
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

pub fn is_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();

    media_type
        .as_bytes()
        .windows(4)
        .any(|w| w.eq_ignore_ascii_case(b"json"))
}
