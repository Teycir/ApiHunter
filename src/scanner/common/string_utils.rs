pub fn redact_secret(s: &str, keep_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= keep_chars * 2 {
        return "*".repeat(chars.len());
    }

    let head: String = chars[..keep_chars].iter().collect();
    let tail: String = chars[chars.len() - keep_chars..].iter().collect();
    let stars = "*".repeat(chars.len().saturating_sub(keep_chars * 2).min(12));
    format!("{head}{stars}{tail}")
}

pub fn snippet(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let boundary = s
            .char_indices()
            .take_while(|&(i, _)| i < max_len)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        format!("{}... ({} bytes total)", &s[..boundary], s.len())
    }
}

pub fn slugify(s: &str) -> String {
    s.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split("--")
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
