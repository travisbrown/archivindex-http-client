//! Retry classification and bounded delays. Callers decide which requests are safe to repeat.

use std::time::Duration;

use crate::Error;
use crate::framing::{ResponseError, Truncation};
mod date;

/// Bounded exponential backoff with Retry-After overrides.
#[derive(Clone, Debug)]
pub struct RetryDelays {
    backoff: Duration,
    maximum: Duration,
}

impl RetryDelays {
    /// Start with an initial delay clamped to the maximum.
    #[must_use]
    pub fn new(initial: Duration, maximum: Duration) -> Self {
        Self {
            backoff: initial.min(maximum),
            maximum,
        }
    }

    /// Double the backoff without exceeding the maximum or overflowing.
    pub fn advance(&mut self) {
        self.backoff = self
            .backoff
            .checked_mul(2)
            .unwrap_or(self.maximum)
            .min(self.maximum);
    }

    /// The current backoff when no response supplies Retry-After.
    #[must_use]
    pub const fn backoff(&self) -> Duration {
        self.backoff
    }

    /// The delay a `Retry-After` value asks for, or the backoff when there is none or it cannot be
    /// read, capped at the maximum.
    #[must_use]
    pub fn for_retry_after(
        &self,
        value: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Duration {
        value
            .and_then(|value| parse_retry_after(value, now))
            .unwrap_or(self.backoff)
            .min(self.maximum)
    }
}

/// Whether a status is commonly retried by an HTTP client.
#[must_use]
pub const fn is_retryable_status(status: u16) -> bool {
    status == 429 || matches!(status, 500 | 502 | 503 | 504)
}

/// Interpret a `Retry-After` value as a delay.
///
/// RFC 9110 defines the value as a number of seconds or an HTTP-date, and a date that has already
/// passed asks for no delay at all.
#[must_use]
pub fn parse_retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse() {
        return Some(Duration::from_secs(seconds));
    }

    let delay = (date::parse(value, now)? - now).to_std();

    Some(delay.unwrap_or(Duration::ZERO))
}

/// Whether an incomplete capture may succeed on another attempt.
#[must_use]
pub const fn is_retryable_truncation(reason: Option<Truncation>) -> bool {
    matches!(reason, Some(Truncation::Disconnect | Truncation::Time))
}

/// Whether a failure is an I/O error or a disconnect before complete response headers.
#[must_use]
pub const fn is_transient(error: &Error) -> bool {
    matches!(
        error,
        Error::Io(_) | Error::Response(ResponseError::IncompleteHeaderSection)
    )
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn retry_delays_clamp_initial_values_and_overflowing_growth() {
        let delays = RetryDelays::new(Duration::MAX, Duration::from_secs(5));
        assert_eq!(delays.backoff, Duration::from_secs(5));

        let mut delays = RetryDelays::new(Duration::MAX, Duration::MAX);
        delays.advance();
        assert_eq!(delays.backoff, Duration::MAX);
    }

    #[test]
    fn retry_after_accepts_seconds_and_http_dates() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();

        assert_eq!(
            parse_retry_after(" 42 ", now),
            Some(Duration::from_secs(42))
        );
        assert_eq!(
            parse_retry_after("Fri, 21 Aug 2026 12:01:00 GMT", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Friday, 21-Aug-26 12:01:00 GMT", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Fri Aug 21 12:01:00 2026", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Fri, 21 Aug 2026 12:01:00 +0000", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Fri, 21 Aug 2026 11:59:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("not a delay", now), None);
    }

    #[test]
    fn a_past_retry_after_date_overrides_the_backoff() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
        let delays = RetryDelays::new(Duration::from_secs(5), Duration::from_secs(60));

        assert_eq!(
            delays.for_retry_after(Some("Fri, 21 Aug 2026 11:59:00 GMT"), now),
            Duration::ZERO
        );
        assert_eq!(
            delays.for_retry_after(Some("not a delay"), now),
            Duration::from_secs(5)
        );
        assert_eq!(delays.for_retry_after(None, now), Duration::from_secs(5));
    }

    #[test]
    fn retry_classification_distinguishes_limits_from_transport_failures() {
        for status in [429, 500, 502, 503, 504] {
            assert!(is_retryable_status(status));
        }
        for status in [200, 301, 304, 404, 501] {
            assert!(!is_retryable_status(status));
        }
        assert!(!is_retryable_truncation(Some(Truncation::Length)));
        assert!(!is_retryable_truncation(None));
        assert!(is_retryable_truncation(Some(Truncation::Time)));
        assert!(is_retryable_truncation(Some(Truncation::Disconnect)));
        assert!(is_transient(
            &std::io::Error::from(std::io::ErrorKind::ConnectionReset).into()
        ));
        assert!(is_transient(&ResponseError::IncompleteHeaderSection.into()));
        assert!(!is_transient(
            &ResponseError::ConflictingContentLength.into()
        ));
    }
}
