use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
    collections::HashMap,
};
use tokio;
use test_log::test;
use criterion::{criterion_group, criterion_main, Criterion};
use metrics::{counter, gauge, histogram};

// Re-export test modules
pub mod security_tests;
pub mod ml_tests;
pub mod storage_tests;

// Test constants aligned with SLAs
const TEST_CONFIG_PATH: &str = "test_config.json";
const TEST_DIR_PREFIX: &str = "guardian_integration_test_";
const RESOURCE_THRESHOLD_CPU: f64 = 5.0; // 5% max CPU overhead
const RESOURCE_THRESHOLD_MEMORY: f64 = 5.0; // 5% max memory overhead
const PERFORMANCE_THRESHOLD_MS: u64 = 1000; // 1s max response time

/// Enhanced test context with resource monitoring and isolation
#[derive(Debug)]
pub struct TestContext {
    test_dir: PathBuf,
    config: TestConfig,
    resource_monitor: ResourceMonitor,
    metrics_collector: Arc<MetricsCollector>,
    benchmark_suite: BenchmarkSuite,
}

impl TestContext {
    /// Creates a new test context with monitoring capabilities
    pub async fn new(config: TestConfig) -> Result<Self, GuardianError> {
        // Create isolated test directory
        let test_dir = std::env::temp_dir().join(format!(
            "{}_{}", 
            TEST_DIR_PREFIX,
            uuid::Uuid::new_v4()
        ));
        tokio::fs::create_dir_all(&test_dir).await?;

        // Initialize metrics collection
        let metrics_config = MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(1000),
            flush_interval: Some(Duration::from_secs(1)),
            sampling_rates: None,
        };
        let metrics_collector = Arc::new(MetricsCollector::new(metrics_config)?);

        // Initialize resource monitoring
        let resource_monitor = ResourceMonitor::new(
            RESOURCE_THRESHOLD_CPU,
            RESOURCE_THRESHOLD_MEMORY,
            metrics_collector.clone(),
        );

        // Initialize benchmark suite
        let benchmark_suite = BenchmarkSuite::new(
            PERFORMANCE_THRESHOLD_MS,
            metrics_collector.clone(),
        );

        Ok(Self {
            test_dir,
            config,
            resource_monitor,
            metrics_collector,
            benchmark_suite,
        })
    }

    /// Performs comprehensive cleanup of test resources
    pub async fn cleanup(&self) -> Result<(), GuardianError> {
        // Stop resource monitoring
        self.resource_monitor.stop().await?;

        // Collect final metrics
        let final_metrics = self.metrics_collector.collect_metrics(None).await?;
        for metric in final_metrics {
            gauge!(
                &metric.name,
                metric.value,
                "test_phase" => "cleanup"
            );
        }

        // Generate test reports
        self.benchmark_suite.generate_report().await?;

        // Clean up test directory
        tokio::fs::remove_dir_all(&self.test_dir).await?;

        Ok(())
    }

    /// Monitors system resource usage during tests
    pub async fn monitor_resources(&self) -> ResourceMetrics {
        self.resource_monitor.get_metrics().await
    }
}

/// Sets up the global test environment with advanced resource monitoring
#[tokio::test]
pub async fn setup_test_environment(config: TestConfig) -> Result<TestContext, GuardianError> {
    // Initialize test logging
    test_log::init();

    // Create test context with monitoring
    let context = TestContext::new(config).await?;

    // Start resource monitoring
    context.resource_monitor.start().await?;

    // Configure performance benchmarks
    context.benchmark_suite.configure(
        criterion::Criterion::default()
            .sample_size(100)
            .measurement_time(Duration::from_secs(10))
    );

    Ok(context)
}

/// Executes system performance benchmarks
#[criterion]
pub async fn benchmark_system_performance(context: &TestContext) -> Result<BenchmarkResults, GuardianError> {
    let mut results = BenchmarkResults::default();

    // Security performance benchmarks
    results.security_metrics = security_tests::test_threat_detection_performance().await?;

    // ML inference benchmarks
    results.ml_metrics = ml_tests::test_inference_performance().await?;

    // Storage performance benchmarks
    results.storage_metrics = storage_tests::test_storage_performance().await?;

    // Validate against SLAs
    assert!(results.security_metrics.avg_detection_time_ms < 100.0);
    assert!(results.ml_metrics.avg_inference_time_ms < 100.0);
    assert!(results.storage_metrics.avg_write_latency_ms < 100.0);

    // Record benchmark metrics
    context.metrics_collector.record_metric(
        "benchmark.security.detection_time_ms".into(),
        results.security_metrics.avg_detection_time_ms,
        MetricType::Gauge,
        MetricPriority::High,
        None,
    ).await?;

    Ok(results)
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = benchmark_system_performance
);
criterion_main!(benches);