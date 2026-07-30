//! Lightweight metrics collection for steganography pipelines.
//!
//! Provides [`StegoMetrics`] for tracking frame processing statistics,
//! signing latency, and verification success/failure rates.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
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
    /// OpenTimestamps proofs generated.
    ots_proofs_generated: AtomicU64,
    /// OpenTimestamps proofs that verified successfully.
    ots_verifications_passed: AtomicU64,
    /// OpenTimestamps proofs that failed verification.
    ots_verifications_failed: AtomicU64,
    /// Unix timestamp of the last OTS attestation (seconds), or 0 if none.
    ots_last_timestamp: AtomicI64,
    /// Whether the last OTS verification succeeded.
    ots_last_verified: AtomicBool,
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
            ots_proofs_generated: AtomicU64::new(0),
            ots_verifications_passed: AtomicU64::new(0),
            ots_verifications_failed: AtomicU64::new(0),
            ots_last_timestamp: AtomicI64::new(0),
            ots_last_verified: AtomicBool::new(false),
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

    /// Record that an OTS proof was generated.
    pub fn record_ots_proof(&self) {
        self.ots_proofs_generated.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the result of an OTS proof verification.
    pub fn record_ots_verification(&self, verified: bool, timestamp: Option<u64>) {
        if verified {
            self.ots_verifications_passed
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.ots_verifications_failed
                .fetch_add(1, Ordering::Relaxed);
        }
        self.ots_last_verified.store(verified, Ordering::Relaxed);
        if let Some(ts) = timestamp {
            self.ots_last_timestamp.store(ts as i64, Ordering::Relaxed);
        }
    }

    /// Get total OTS proofs generated.
    pub fn ots_proofs_generated(&self) -> u64 {
        self.ots_proofs_generated.load(Ordering::Relaxed)
    }

    /// Get OTS verifications passed.
    pub fn ots_verifications_passed(&self) -> u64 {
        self.ots_verifications_passed.load(Ordering::Relaxed)
    }

    /// Get OTS verifications failed.
    pub fn ots_verifications_failed(&self) -> u64 {
        self.ots_verifications_failed.load(Ordering::Relaxed)
    }

    /// Get the last OTS attestation timestamp (Unix seconds), or 0 if none.
    pub fn ots_last_timestamp(&self) -> i64 {
        self.ots_last_timestamp.load(Ordering::Relaxed)
    }

    /// Whether the last OTS verification succeeded.
    pub fn ots_last_verified(&self) -> bool {
        self.ots_last_verified.load(Ordering::Relaxed)
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
            "ots_proofs_generated": self.ots_proofs_generated(),
            "ots_verifications_passed": self.ots_verifications_passed(),
            "ots_verifications_failed": self.ots_verifications_failed(),
            "ots_last_timestamp": self.ots_last_timestamp(),
            "ots_last_verified": self.ots_last_verified(),
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
        self.ots_proofs_generated.store(0, Ordering::Relaxed);
        self.ots_verifications_passed.store(0, Ordering::Relaxed);
        self.ots_verifications_failed.store(0, Ordering::Relaxed);
        self.ots_last_timestamp.store(0, Ordering::Relaxed);
        self.ots_last_verified.store(false, Ordering::Relaxed);
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

    #[test]
    fn test_ots_metrics() {
        let metrics = StegoMetrics::new();
        assert_eq!(metrics.ots_proofs_generated(), 0);
        assert_eq!(metrics.ots_verifications_passed(), 0);
        assert_eq!(metrics.ots_verifications_failed(), 0);
        assert_eq!(metrics.ots_last_timestamp(), 0);
        assert!(!metrics.ots_last_verified());

        metrics.record_ots_proof();
        metrics.record_ots_proof();
        assert_eq!(metrics.ots_proofs_generated(), 2);

        metrics.record_ots_verification(true, Some(1700000000));
        assert_eq!(metrics.ots_verifications_passed(), 1);
        assert_eq!(metrics.ots_last_timestamp(), 1700000000);
        assert!(metrics.ots_last_verified());

        metrics.record_ots_verification(false, None);
        assert_eq!(metrics.ots_verifications_failed(), 1);
        assert!(!metrics.ots_last_verified());
    }

    #[test]
    fn test_ots_metrics_json() {
        let metrics = StegoMetrics::new();
        metrics.record_ots_proof();
        metrics.record_ots_verification(true, Some(123));
        let json = metrics.to_json();
        assert!(json.contains("\"ots_proofs_generated\":1"));
        assert!(json.contains("\"ots_verifications_passed\":1"));
        assert!(json.contains("\"ots_last_timestamp\":123"));
        assert!(json.contains("\"ots_last_verified\":true"));
    }

    #[test]
    fn test_ots_metrics_reset() {
        let metrics = StegoMetrics::new();
        metrics.record_ots_proof();
        metrics.record_ots_verification(true, Some(999));
        metrics.reset();
        assert_eq!(metrics.ots_proofs_generated(), 0);
        assert_eq!(metrics.ots_verifications_passed(), 0);
        assert_eq!(metrics.ots_last_timestamp(), 0);
        assert!(!metrics.ots_last_verified());
    }
}
