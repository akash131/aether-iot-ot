//! Service telemetry shared by the control plane and the edge (ZTE-IOT
//! section 120 Observability; ZTE-IOT-*-i6 metrics, logs and traces
//! sufficient to reconstruct classification, risk and enforcement).
//!
//! * Latency histograms per processing stage (`<prefix>_stage_duration_seconds`).
//! * W3C Trace Context (`traceparent`) parsing, generation and child-span
//!   derivation so that a transaction's correlation identifiers propagate
//!   to every dependency call (platform, peer products) without carrying
//!   credentials or payloads.

use aether_kit::metrics::Metrics;
use prometheus::{HistogramOpts, HistogramVec};
use std::time::Duration;

/// Latency buckets from 50 µs to 30 s.
const BUCKETS: &[f64] = &[0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

#[derive(Clone)]
pub struct Telemetry {
    pub stage_latency: HistogramVec,
}

impl Telemetry {
    pub fn new(metrics: &Metrics, prefix: &str) -> Telemetry {
        let stage_latency = HistogramVec::new(HistogramOpts::new(format!("{prefix}_stage_duration_seconds"), "Processing latency by stage").buckets(BUCKETS.to_vec()), &["stage"])
            .expect("valid histogram");
        let _ = metrics.registry.register(Box::new(stage_latency.clone()));
        Telemetry { stage_latency }
    }

    pub fn observe(&self, stage: &str, d: Duration) {
        self.stage_latency.with_label_values(&[stage]).observe(d.as_secs_f64());
    }

    /// Approximate quantile (upper bucket bound) of a stage from the
    /// histogram, for health summaries and tests.
    pub fn quantile(&self, stage: &str, q: f64) -> Option<f64> {
        let h = self.stage_latency.with_label_values(&[stage]);
        let m = prometheus::core::Metric::metric(&h);
        let hist = m.get_histogram();
        let total = hist.get_sample_count();
        if total == 0 {
            return None;
        }
        let target = (q * total as f64).ceil() as u64;
        hist.get_bucket().iter().find(|b| b.get_cumulative_count() >= target).map(|b| b.get_upper_bound())
    }
}

tokio::task_local! {
    /// Trace context of the transaction being processed by this task.
    pub static TRACE: TraceContext;
}

/// The current task's trace context, or a new root context.
pub fn current_trace() -> TraceContext {
    TRACE.try_with(|t| t.clone()).unwrap_or_default()
}

/// W3C trace context of one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub sampled: bool,
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) && s.bytes().any(|b| b != b'0')
}

impl TraceContext {
    /// A new root context.
    pub fn new() -> TraceContext {
        TraceContext { trace_id: hex::encode(rand::random::<[u8; 16]>()), span_id: hex::encode(rand::random::<[u8; 8]>()), sampled: true }
    }

    /// Parse a `traceparent` header (version 00); invalid values are ignored.
    pub fn parse(header: &str) -> Option<TraceContext> {
        let p: Vec<&str> = header.trim().split('-').collect();
        if p.len() < 4 || p[0] != "00" || !is_hex(p[1], 32) || !is_hex(p[2], 16) || p[3].len() != 2 {
            return None;
        }
        let flags = u8::from_str_radix(p[3], 16).ok()?;
        Some(TraceContext { trace_id: p[1].into(), span_id: p[2].into(), sampled: flags & 1 == 1 })
    }

    /// Continue an incoming context or start a new one.
    pub fn from_header(h: Option<&str>) -> TraceContext {
        h.and_then(Self::parse).map(|c| c.child()).unwrap_or_default()
    }

    /// A child span of this context (same trace).
    pub fn child(&self) -> TraceContext {
        TraceContext { trace_id: self.trace_id.clone(), span_id: hex::encode(rand::random::<[u8; 8]>()), sampled: self.sampled }
    }

    pub fn header(&self) -> String {
        format!("00-{}-{}-{}", self.trace_id, self.span_id, if self.sampled { "01" } else { "00" })
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_context_round_trip_and_validation() {
        let c = TraceContext::new();
        let p = TraceContext::parse(&c.header()).unwrap();
        assert_eq!(p, c);
        let child = c.child();
        assert_eq!(child.trace_id, c.trace_id);
        assert_ne!(child.span_id, c.span_id);
        assert!(TraceContext::parse("00-00000000000000000000000000000000-0000000000000000-01").is_none(), "all-zero ids are invalid");
        assert!(TraceContext::parse("01-x").is_none());
        assert!(TraceContext::parse("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01").is_none(), "upper case is invalid");
        let ok = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00").unwrap();
        assert!(!ok.sampled);
        let cont = TraceContext::from_header(Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"));
        assert_eq!(cont.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(TraceContext::from_header(Some("garbage")).trace_id.len(), 32);
    }

    #[test]
    fn stage_latency_quantiles() {
        let m = Metrics::new("t");
        let t = Telemetry::new(&m, "t");
        assert_eq!(t.quantile("x", 0.5), None);
        for i in 0..100 {
            t.observe("x", Duration::from_micros(if i < 95 { 80 } else { 40_000 }));
        }
        assert_eq!(t.quantile("x", 0.5), Some(0.0001));
        assert_eq!(t.quantile("x", 0.99), Some(0.05));
        assert!(m.render().contains("t_stage_duration_seconds_bucket"));
    }
}
