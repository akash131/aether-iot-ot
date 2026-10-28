//! Dependency-call discipline shared by every outbound call (platform,
//! peer products, vulnerability feeds) (ZTE-IOT-*-i4 explicit timeouts and
//! backpressure, sections 121 SRE and 125 Chaos Engineering: connect
//! timeout, operation timeout, retry budget, jitter, circuit breaking and
//! retryability classes).
//!
//! * [`RetryPolicy`] — bounded attempts, exponential back-off with full
//!   jitter, capped delay.
//! * [`RetryBudget`] — retries may add at most `ratio` extra load on top of
//!   first attempts (token bucket refilled by successful first attempts),
//!   so that a struggling dependency is not overwhelmed by retry storms.
//! * [`Breaker`] — consecutive-failure circuit breaker with closed, open and
//!   half-open states; while open, calls fail fast; after the cool-down one
//!   probe is let through.
//! * [`Retryability`] — classification of an outcome into retryable or
//!   not, and whether it counts against the breaker.

use serde::Serialize;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Timeouts and retries of one dependency.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DependencyPolicy {
    pub connect_timeout: Duration,
    pub operation_timeout: Duration,
    pub retry: RetryPolicy,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy { attempts: 3, base_delay: Duration::from_millis(200), max_delay: Duration::from_secs(5) }
    }
}

impl RetryPolicy {
    /// Delay before retry number `attempt` (0-based): exponential with
    /// jitter in `[base·2^n, base·2^n + base]`, capped at `max_delay`.
    pub fn delay(&self, attempt: u32) -> Duration {
        let exp = self.base_delay.saturating_mul(1u32 << attempt.min(10));
        let jitter_ms = jitter(self.base_delay.as_millis().max(1) as u64);
        (exp + Duration::from_millis(jitter_ms)).min(self.max_delay)
    }
}

/// Uniform pseudo-random value in `0..=max` (xorshift seeded by time and a
/// counter; adequate for jitter, not for cryptography).
fn jitter(max: u64) -> u64 {
    static SEED: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut x = SEED.fetch_add(now_ms() | 1, Ordering::Relaxed) ^ 0x2545_f491_4f6c_dd1d;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x % (max + 1)
}

/// Retry budget: a token bucket; each first attempt deposits `ratio`
/// tokens (capped), each retry withdraws one.
pub struct RetryBudget {
    ratio: f64,
    cap: f64,
    tokens: Mutex<f64>,
}

impl RetryBudget {
    pub fn new(ratio: f64, min_retries: f64) -> Self {
        RetryBudget { ratio, cap: min_retries.max(1.0) * 10.0, tokens: Mutex::new(min_retries) }
    }

    pub fn deposit(&self) {
        let mut t = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        *t = (*t + self.ratio).min(self.cap);
    }

    /// Whether a retry may be attempted now.
    pub fn withdraw(&self) -> bool {
        let mut t = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        if *t >= 1.0 {
            *t -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn available(&self) -> f64 {
        *self.tokens.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for RetryBudget {
    /// Retries may add 20% load, with a floor of 10 retries.
    fn default() -> Self {
        RetryBudget::new(0.2, 10.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Consecutive-failure circuit breaker.
pub struct Breaker {
    threshold: u32,
    open_for: Duration,
    failures: AtomicU32,
    open_until_ms: AtomicU64,
    /// 0 closed, 1 open, 2 half-open (probe in flight)
    state: AtomicU8,
    trips: AtomicU64,
}

impl Breaker {
    pub fn new(threshold: u32, open_for: Duration) -> Self {
        Breaker { threshold: threshold.max(1), open_for, failures: AtomicU32::new(0), open_until_ms: AtomicU64::new(0), state: AtomicU8::new(0), trips: AtomicU64::new(0) }
    }

    /// Whether a call may proceed. While open, fails fast; once the
    /// cool-down has passed, exactly one probe is admitted (half-open).
    pub fn allow(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            0 => true,
            1 if self.open_until_ms.load(Ordering::Acquire) <= now_ms() => self.state.compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire).is_ok(),
            _ => false,
        }
    }

    pub fn state(&self) -> BreakerState {
        match self.state.load(Ordering::Acquire) {
            0 => BreakerState::Closed,
            1 => BreakerState::Open,
            _ => BreakerState::HalfOpen,
        }
    }

    pub fn trips(&self) -> u64 {
        self.trips.load(Ordering::Relaxed)
    }

    pub fn success(&self) {
        self.failures.store(0, Ordering::Release);
        self.state.store(0, Ordering::Release);
    }

    pub fn failure(&self) {
        let half_open = self.state.load(Ordering::Acquire) == 2;
        if half_open || self.failures.fetch_add(1, Ordering::AcqRel) + 1 >= self.threshold {
            self.open_until_ms.store(now_ms() + self.open_for.as_millis() as u64, Ordering::Release);
            self.state.store(1, Ordering::Release);
            self.failures.store(0, Ordering::Release);
            self.trips.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Default for Breaker {
    fn default() -> Self {
        Breaker::new(8, Duration::from_secs(10))
    }
}

/// How an outcome affects retries and the breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Retryability {
    /// Success.
    Success,
    /// The request never reached the dependency (connect refused, DNS):
    /// always safe to retry.
    RetryableBeforeSend,
    /// Overload signals (429, 503) and gateway errors / timeouts: retry
    /// only idempotent operations.
    RetryableIfIdempotent,
    /// Client errors (4xx except 408/429): never retried, not a dependency
    /// failure.
    Permanent,
    /// Other server errors: not retried, counted as dependency failure.
    Failed,
}

impl Retryability {
    /// Classify an HTTP status.
    pub fn from_status(status: u16) -> Retryability {
        match status {
            200..=399 => Retryability::Success,
            408 | 429 | 502 | 503 | 504 => Retryability::RetryableIfIdempotent,
            400..=499 => Retryability::Permanent,
            _ => Retryability::Failed,
        }
    }

    pub fn may_retry(&self, idempotent: bool) -> bool {
        match self {
            Retryability::RetryableBeforeSend => true,
            Retryability::RetryableIfIdempotent => idempotent,
            _ => false,
        }
    }

    pub fn is_dependency_failure(&self) -> bool {
        matches!(self, Retryability::RetryableBeforeSend | Retryability::RetryableIfIdempotent | Retryability::Failed)
    }
}

/// Health summary of a dependency for health endpoints and heartbeats.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyHealth {
    pub name: String,
    pub breaker: BreakerState,
    pub trips: u64,
    pub retry_budget: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_with_jitter_is_bounded() {
        let p = RetryPolicy::default();
        for a in 0..5 {
            let d = p.delay(a);
            let floor = p.base_delay.saturating_mul(1 << a).min(p.max_delay);
            assert!(d >= floor && d <= p.max_delay, "attempt {a}: {d:?}");
        }
        assert_eq!(p.delay(30), p.max_delay);
    }

    #[test]
    fn retry_budget_limits_retry_storms() {
        let b = RetryBudget::new(0.2, 2.0);
        assert!(b.withdraw() && b.withdraw());
        assert!(!b.withdraw(), "budget exhausted");
        for _ in 0..5 {
            b.deposit();
        }
        assert!(b.withdraw(), "five first attempts earn one retry");
        assert!(!b.withdraw());
    }

    #[test]
    fn breaker_opens_probes_and_recovers() {
        let b = Breaker::new(3, Duration::from_millis(30));
        assert!(b.allow());
        b.failure();
        b.failure();
        assert_eq!(b.state(), BreakerState::Closed);
        b.failure();
        assert_eq!((b.state(), b.allow(), b.trips()), (BreakerState::Open, false, 1));
        std::thread::sleep(Duration::from_millis(40));
        assert!(b.allow(), "one probe after the cool-down");
        assert!(!b.allow(), "only one probe at a time");
        b.failure();
        assert_eq!(b.state(), BreakerState::Open, "a failed probe re-opens");
        std::thread::sleep(Duration::from_millis(40));
        assert!(b.allow());
        b.success();
        assert_eq!((b.state(), b.allow()), (BreakerState::Closed, true));
    }

    #[test]
    fn retryability_classes() {
        use Retryability::*;
        assert_eq!(Retryability::from_status(200), Success);
        assert_eq!(Retryability::from_status(503), RetryableIfIdempotent);
        assert_eq!(Retryability::from_status(404), Permanent);
        assert_eq!(Retryability::from_status(500), Failed);
        assert!(RetryableIfIdempotent.may_retry(true) && !RetryableIfIdempotent.may_retry(false));
        assert!(RetryableBeforeSend.may_retry(false));
        assert!(!Permanent.is_dependency_failure() && Failed.is_dependency_failure());
    }
}
