//! Prometheus metrics setup.

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

static PROM_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Installs the global metrics recorder (idempotently) and returns the rendering handle.
///
/// The exported metrics are:
/// - `pii_requests_total{endpoint,status}`
/// - `pii_request_duration_seconds{endpoint}` (histogram)
/// - `pii_detections_total{entity_type}`
pub fn install() -> PrometheusHandle {
    PROM_HANDLE
        .get_or_init(|| {
            let handle = PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Full("pii_request_duration_seconds".to_string()),
                    &[
                        0.000_100, 0.000_250, 0.000_500, 0.001_000, 0.002_500, 0.005_000,
                        0.010_000, 0.050_000, 0.100_000, 0.250_000, 0.500_000, 1.000_000,
                        2.500_000, 5.000_000, 10.000_000,
                    ],
                )
                .expect("valid histogram buckets")
                .install_recorder()
                .expect("failed to install prometheus recorder");

            // Pre-declare counters so they appear (at 0) before the first request.
            metrics::counter!("pii_requests_total", "endpoint" => "redact", "status" => "200")
                .increment(0);
            metrics::counter!("pii_detections_total", "entity_type" => "none").increment(0);

            handle
        })
        .clone()
}
