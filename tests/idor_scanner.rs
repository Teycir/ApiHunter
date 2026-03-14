// tests/idor_scanner.rs
//
// Unit tests for IDOR/BOLA detection helper functions and logic.

#[cfg(test)]
mod idor_tests {
    use url::Url;

    /// Type alias for IDOR scan results: (resource_id, status_code, fingerprint)
    type ScanResult = (u64, u16, Option<(usize, u64)>);

    /// Helper: find numeric segment in URL path
    fn find_numeric_segment(url: &str) -> Option<(usize, u64)> {
        let parsed = Url::parse(url).ok()?;
        let segments: Vec<String> = parsed.path_segments()?.map(|s| s.to_string()).collect();

        for (i, seg) in segments.iter().enumerate().rev() {
            if let Ok(num) = seg.parse::<u64>() {
                if num < 10_000_000_000 {
                    return Some((i, num));
                }
            }
        }
        None
    }

    /// Helper: replace numeric segment with new ID
    fn replace_numeric_segment(url: &str, segment_index: usize, new_id: u64) -> String {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return url.to_string(),
        };
        let mut segments: Vec<String> = match parsed.path_segments() {
            Some(s) => s.map(|s| s.to_string()).collect(),
            None => return url.to_string(),
        };

        segments[segment_index] = new_id.to_string();
        let new_path = format!("/{}", segments.join("/"));
        let mut new_url = parsed.clone();
        new_url.set_path(&new_path);
        new_url.to_string()
    }

    #[test]
    fn test_find_numeric_segment_basic() {
        let url = "https://api.example.com/users/42";
        let result = find_numeric_segment(url);
        assert_eq!(result, Some((1, 42)), "Should find numeric segment 42");
    }

    #[test]
    fn test_find_numeric_segment_multiple() {
        let url = "https://api.example.com/api/v1/orders/99/items/5";
        let result = find_numeric_segment(url);
        // Path segments: ["api", "v1", "orders", "99", "items", "5"]
        // Index 5 is the rightmost numeric segment ("5")
        assert_eq!(
            result,
            Some((5, 5)),
            "Should find rightmost numeric segment at index 5"
        );
    }

    #[test]
    fn test_find_numeric_segment_no_numeric() {
        let url = "https://api.example.com/users/profile";
        let result = find_numeric_segment(url);
        assert_eq!(result, None, "Should return None when no numeric segment");
    }

    #[test]
    fn test_find_numeric_segment_large_timestamp() {
        let url = "https://api.example.com/events/1704067200";
        let result = find_numeric_segment(url);
        // 1704067200 is a realistic timestamp but < 10 billion
        assert_eq!(result, Some((1, 1704067200)));
    }

    #[test]
    fn test_find_numeric_segment_huge_timestamp_ignored() {
        let url = "https://api.example.com/events/17040672000000";
        let result = find_numeric_segment(url);
        // > 10 billion should be ignored (likely microsecond timestamp)
        assert_eq!(
            result, None,
            "Should ignore very large numbers (timestamps)"
        );
    }

    #[test]
    fn test_replace_numeric_segment() {
        let url = "https://api.example.com/users/42";
        let new_url = replace_numeric_segment(url, 1, 43);
        assert_eq!(new_url, "https://api.example.com/users/43");
    }

    #[test]
    fn test_replace_numeric_segment_nested() {
        let url = "https://api.example.com/api/v1/orders/99/items/5";
        // Path segments: ["api", "v1", "orders", "99", "items", "5"]
        // Index 5 is "5", so replace it with 6
        let new_url = replace_numeric_segment(url, 5, 6);
        assert_eq!(new_url, "https://api.example.com/api/v1/orders/99/items/6");
    }

    #[test]
    fn test_replace_numeric_segment_with_query() {
        let url = "https://api.example.com/users/42?expand=profile";
        let new_url = replace_numeric_segment(url, 1, 43);
        assert_eq!(new_url, "https://api.example.com/users/43?expand=profile");
    }

    #[test]
    fn test_replace_numeric_segment_invalid_url() {
        let url = "not a url";
        let new_url = replace_numeric_segment(url, 0, 10);
        // Should return original on parse failure
        assert_eq!(new_url, url);
    }

    /// Body fingerprinting logic
    fn body_fingerprint(body: &str) -> (usize, u64) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let prefix: String = body.chars().take(256).collect();
        let mut h = DefaultHasher::new();
        prefix.hash(&mut h);
        (body.len(), h.finish())
    }

    #[test]
    fn test_body_fingerprint_same_content() {
        let body1 = r#"{"id":42,"email":"user@example.com","data":"secret"}"#;
        let body2 = r#"{"id":42,"email":"user@example.com","data":"secret"}"#;

        let fp1 = body_fingerprint(body1);
        let fp2 = body_fingerprint(body2);

        assert_eq!(fp1, fp2, "Same content should produce same fingerprint");
    }

    #[test]
    fn test_body_fingerprint_different_content() {
        let body1 = r#"{"id":42,"email":"user@example.com"}"#;
        let body2 = r#"{"id":43,"email":"other@example.com"}"#;

        let fp1 = body_fingerprint(body1);
        let fp2 = body_fingerprint(body2);

        assert_ne!(
            fp1, fp2,
            "Different content should produce different fingerprint"
        );
    }

    #[test]
    fn test_body_fingerprint_only_uses_prefix() {
        // Bodies with identical first 256 chars but different suffix lengths
        let shared_prefix = "a".repeat(256);
        let body1 = format!("{}x", &shared_prefix);
        let body2 = format!("{}xxxx", &shared_prefix);

        let fp1 = body_fingerprint(&body1);
        let fp2 = body_fingerprint(&body2);

        // Same first 256 chars should give same hash (but different sizes mean different fingerprints)
        assert_eq!(fp1.1, fp2.1, "Hash of first 256 chars should be identical");
        // But body lengths are different
        assert_ne!(fp1.0, fp2.0, "Body lengths are different");
    }

    #[test]
    fn test_body_fingerprint_size_difference() {
        let body1 = r#"{"small":1}"#;
        let body2 = format!(r#"{{"size":1}}{}"#, "x".repeat(5000));

        let fp1 = body_fingerprint(body1);
        let fp2 = body_fingerprint(&body2);

        // Different sizes means different fingerprint(size is part of tuple)
        assert_ne!(
            fp1, fp2,
            "Different body lengths should differ in fingerprint"
        );
    }

    #[test]
    fn test_id_range_pattern_detection() {
        // Simulate tier 2 logic: multiple adjacent IDs all return same content
        let base_id = 42u64;
        let _range_ids: Vec<u64> = (base_id.saturating_sub(2)..=base_id + 2).collect();

        // All IDs return same fingerprint => enumerable
        let fp = (100, 12345u64);
        let results: Vec<ScanResult> = vec![
            (40, 200, Some(fp)),
            (41, 200, Some(fp)),
            (42, 200, Some(fp)),
            (43, 200, Some(fp)),
            (44, 200, Some(fp)),
        ];

        let other_successes: Vec<_> = results
            .iter()
            .filter(|(id, status, fp)| {
                *id != base_id && *status < 400 && fp.as_ref().map(|f| f.0 > 32).unwrap_or(false)
            })
            .collect();

        assert!(
            other_successes.len() >= 2,
            "Should detect 2+ adjacent IDs with 200"
        );
    }

    // Tier 2 fires on adjacent IDs returning 200, regardless of body similarity.
    #[test]
    fn test_id_range_adjacent_ids_counted_regardless_of_content() {
        let base_id = 42u64;
        let base_fp = (100, 12345u64);

        // Different content for each ID => not enumerable
        let results: Vec<ScanResult> = vec![
            (40, 200, Some((100, 11111u64))),
            (41, 200, Some((100, 22222u64))),
            (42, 200, Some(base_fp)),
            (43, 200, Some((100, 44444u64))),
            (44, 200, Some((100, 55555u64))),
        ];

        let other_successes: Vec<_> = results
            .iter()
            .filter(|(id, status, fp)| *id != base_id && *status < 400 && fp.is_some())
            .collect();

        // Even though multiple IDs return 200, they're all different
        assert_eq!(other_successes.len(), 4);
    }

    #[test]
    fn test_tier2_403_responses_not_counted() {
        let base_id = 42u64;
        let success_fp = Some((100, 12345u64));

        // Only base ID returns 200; others return 403 (correct auth enforcement)
        let results: Vec<(u64, u16, Option<(usize, u64)>)> = vec![
            (40, 403, None),
            (41, 403, None),
            (42, 200, success_fp),
            (43, 403, None),
            (44, 403, None),
        ];

        let other_successes: Vec<_> = results
            .iter()
            .filter(|(id, status, fp)| *id != base_id && *status < 400 && fp.is_some())
            .collect();

        assert_eq!(other_successes.len(), 0, "Should not count 403 responses");
    }
}
