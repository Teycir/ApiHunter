use std::time::Duration;

/// Retryable HTTP statuses for transient upstream/CDN failures.
pub fn should_retry_status(status: u16) -> bool {
    matches!(
        status,
        429 | 500 | 502 | 503 | 504 | 520 | 521 | 522 | 523 | 524
    )
}

/// Exponential backoff: 200ms * 2^attempt, capped at attempt=6.
pub fn retry_backoff(attempt: u32) -> Duration {
    let shift = attempt.min(6);
    let exp = 1u64 << shift;
    Duration::from_millis(200 * exp)
}
