//! Lightweight metrics collection for steganography pipelines.
//!
//! Provides [`StegoMetrics`] for tracking frame processing statistics,
//! signing latency, and verification success/failure rates.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Thread-safe metrics collector for steganography pipeline performance.
///
/// Uses atomic counters for lock-free concurrent access from
/// GStreamer callback threads.
#[derive(Debug)]
pub struct StegoMetrics {
    /// Total frames processed.
    frames_processed: AtomicU64,
    /// Total frames successfully verified.
    frames_verified_ok: AtomicU64,
    /// Total frames that failed verification.
    frames_verified_fail: AtomicU64,
    /// Cumulative signing time in microseconds.
    total_sign_us: AtomicU64,
    /// Cumulative verify time in microseconds.
    total_verify_us: AtomicU64,
    /// Cumulative embed time in microseconds.
    total_embed_us: AtomicU64,
    /// Timestamp when metrics collection started.
    start_time: Instant,
}

impl StegoMetrics {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self {
            frames_processed: AtomicU64::new(0),
            frames_verified_ok: AtomicU64::new(0),
            frames_verified_fail: AtomicU64::new(0),
            total_sign_us: AtomicU64::new(0),
            total_verify_us: AtomicU64::new(0),
            total_embed_us: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Record a frame being processed.
    pub fn record_frame(&self) {
        self.frames_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful verification.
    pub fn record_verify_ok(&self) {
        self.frames_verified_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed verification.
    pub fn record_verify_fail(&self) {
        self.frames_verified_fail.fetch_add(1, Ordering::Relaxed);
    }

    /// Record signing duration.
    pub fn record_sign_duration(&self, duration: std::time::Duration) {
        self.total_sign_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record verification duration.
    pub fn record_verify_duration(&self, duration: std::time::Duration) {
        self.total_verify_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record embedding duration.
    pub fn record_embed_duration(&self, duration: std::time::Duration) {
        self.total_embed_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Get total frames processed.
    pub fn frames_processed(&self) -> u64 {
        self.frames_processed.load(Ordering::Relaxed)
    }

    /// Get verified OK count.
    pub fn frames_verified_ok(&self) -> u64 {
        self.frames_verified_ok.load(Ordering::Relaxed)
    }

    /// Get verified FAIL count.
    pub fn frames_verified_fail(&self) -> u64 {
        self.frames_verified_fail.load(Ordering::Relaxed)
    }

    /// Get elapsed time since metrics started.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Compute average FPS over the collection period.
    pub fn average_fps(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.frames_processed() as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Average signing latency in microseconds.
    pub fn avg_sign_latency_us(&self) -> f64 {
        let frames = self.frames_processed();
        if frames > 0 {
            self.total_sign_us.load(Ordering::Relaxed) as f64 / frames as f64
        } else {
            0.0
        }
    }

    /// Average verify latency in microseconds.
    pub fn avg_verify_latency_us(&self) -> f64 {
        let verified = self.frames_verified_ok() + self.frames_verified_fail();
        if verified > 0 {
            self.total_verify_us.load(Ordering::Relaxed) as f64 / verified as f64
        } else {
            0.0
        }
    }

    /// Serialize metrics to JSON string for dashboard consumption.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "frames_processed": self.frames_processed(),
            "frames_verified_ok": self.frames_verified_ok(),
            "frames_verified_fail": self.frames_verified_fail(),
            "average_fps": format!("{:.1}", self.average_fps()),
            "avg_sign_latency_us": format!("{:.1}", self.avg_sign_latency_us()),
            "avg_verify_latency_us": format!("{:.1}", self.avg_verify_latency_us()),
            "uptime_secs": format!("{:.1}", self.elapsed().as_secs_f64()),
        })
        .to_string()
    }

    /// Reset all counters (preserves start time).
    pub fn reset(&self) {
        self.frames_processed.store(0, Ordering::Relaxed);
        self.frames_verified_ok.store(0, Ordering::Relaxed);
        self.frames_verified_fail.store(0, Ordering::Relaxed);
        self.total_sign_us.store(0, Ordering::Relaxed);
        self.total_verify_us.store(0, Ordering::Relaxed);
        self.total_embed_us.store(0, Ordering::Relaxed);
    }
}

impl Default for StegoMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_basic() {
        let metrics = StegoMetrics::new();
        assert_eq!(metrics.frames_processed(), 0);
        assert_eq!(metrics.frames_verified_ok(), 0);
        assert_eq!(metrics.frames_verified_fail(), 0);

        metrics.record_frame();
        metrics.record_frame();
        metrics.record_verify_ok();
        metrics.record_verify_fail();

        assert_eq!(metrics.frames_processed(), 2);
        assert_eq!(metrics.frames_verified_ok(), 1);
        assert_eq!(metrics.frames_verified_fail(), 1);
    }

    #[test]
    fn test_metrics_latency() {
        let metrics = StegoMetrics::new();
        metrics.record_frame();
        metrics.record_sign_duration(Duration::from_micros(100));
        metrics.record_frame();
        metrics.record_sign_duration(Duration::from_micros(200));

        assert!((metrics.avg_sign_latency_us() - 150.0).abs() < 1.0);
    }

    #[test]
    fn test_metrics_json() {
        let metrics = StegoMetrics::new();
        metrics.record_frame();
        let json = metrics.to_json();
        assert!(json.contains("\"frames_processed\":1"));
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = StegoMetrics::new();
        metrics.record_frame();
        metrics.record_verify_ok();
        metrics.reset();
        assert_eq!(metrics.frames_processed(), 0);
        assert_eq!(metrics.frames_verified_ok(), 0);
    }

    #[test]
    fn test_metrics_default() {
        let metrics = StegoMetrics::default();
        assert_eq!(metrics.frames_processed(), 0);
    }
}
