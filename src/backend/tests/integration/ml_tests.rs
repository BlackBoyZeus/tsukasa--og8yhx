use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio;
use tracing::{info, warn};
use test_log::test;
use criterion::{criterion_group, criterion_main, Criterion};
use metrics::{counter, gauge, histogram};

use guardian_ml::{
    model_registry::ModelRegistry,
    inference_engine::InferenceEngine,
};

// Test constants
const TEST_MODEL_PATH: &str = "test_models/guardian_test";
const TEST_BATCH_SIZE: usize = 64;
const PERFORMANCE_THRESHOLD_MS: u64 = 100;
const ACCURACY_THRESHOLD: f64 = 0.99999;
const RESOURCE_USAGE_THRESHOLD: f64 = 0.05;
const MAX_CONCURRENT_TESTS: usize = 4;

/// Enhanced test context with monitoring capabilities
#[derive(Debug)]
struct TestContext {
    model_registry: Arc<ModelRegistry>,
    inference_engine: Arc<InferenceEngine>,
    metrics_collector: Arc<MetricsCollector>,
}

impl TestContext {
    /// Creates a new TestContext instance with monitoring
    async fn new(
        model_registry: Arc<ModelRegistry>,
        inference_engine: Arc<InferenceEngine>,
        metrics_collector: Arc<MetricsCollector>,
    ) -> Self {
        Self {
            model_registry,
            inference_engine,
            metrics_collector,
        }
    }

    /// Records test metrics
    async fn record_metric(&self, name: &str, value: f64, tags: Option<HashMap<String, String>>) {
        self.metrics_collector
            .record_metric(
                name.to_string(),
                value,
                MetricType::Gauge,
                MetricPriority::High,
                tags,
            )
            .await
            .expect("Failed to record test metric");
    }
}

/// Sets up the test environment with required ML components and monitoring
async fn setup_test_environment() -> Result<TestContext, GuardianError> {
    // Initialize metrics collection
    let metrics_config = MetricsConfig {
        statsd_host: "localhost".into(),
        statsd_port: 8125,
        buffer_size: Some(1000),
        flush_interval: Some(Duration::from_secs(1)),
        sampling_rates: None,
    };
    let metrics_collector = Arc::new(MetricsCollector::new(metrics_config)?);

    // Initialize model registry
    let model_store = Arc::new(ModelStore::new(
        Arc::new(ZfsManager::new(
            "testpool".to_string(),
            vec![0u8; 32],
            Arc::new(LogManager::new()),
            None,
        ).await?),
        std::path::PathBuf::from(TEST_MODEL_PATH),
        Some(5),
    ).await?);
    let model_registry = Arc::new(ModelRegistry::new(model_store).await?);

    // Initialize feature extractor
    let feature_extractor = Arc::new(FeatureExtractor::new(
        CoreMetricsManager::new(
            metrics_collector.clone(),
            MetricsConfig {
                sampling_rates: HashMap::new(),
                priority_levels: HashMap::new(),
                buffer_size: 1000,
            },
        )?,
        None,
    ));

    // Initialize inference engine
    let inference_engine = Arc::new(InferenceEngine::new(
        model_registry.clone(),
        feature_extractor,
        InferenceConfig::default(),
    ).await?);

    Ok(TestContext::new(
        model_registry,
        inference_engine,
        metrics_collector,
    ).await)
}

/// Tests model registration workflow with security validation
#[tokio::test]
async fn test_model_registration() -> Result<(), GuardianError> {
    let ctx = setup_test_environment().await?;
    let start_time = Instant::now();

    // Create test model with valid signature
    let test_model_data = vec![1u8; 1024];
    let version = "v1.0.0".to_string();
    let metadata = ModelMetadata {
        name: "test_model".to_string(),
        version: version.clone(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        status: ModelStatus::Inactive,
        metrics: None,
        validation_status: ValidationStatus::Pending,
        hash: "".to_string(),
        size_bytes: test_model_data.len() as u64,
    };

    // Test model registration
    let result = ctx.model_registry
        .register_model(test_model_data.clone(), version.clone(), metadata)
        .await?;
    assert_eq!(result.status, ModelStatus::Inactive);

    // Test invalid signature
    let invalid_model = vec![0u8; 1024];
    let invalid_result = ctx.model_registry
        .register_model(invalid_model, "v1.0.1".to_string(), metadata.clone())
        .await;
    assert!(invalid_result.is_err());

    // Test concurrent model registration
    let mut handles = Vec::new();
    for i in 0..MAX_CONCURRENT_TESTS {
        let registry = ctx.model_registry.clone();
        let version = format!("v1.0.{}", i);
        let metadata = metadata.clone();
        let test_data = test_model_data.clone();

        handles.push(tokio::spawn(async move {
            registry.register_model(test_data, version, metadata).await
        }));
    }

    for handle in handles {
        handle.await.expect("Task failed").expect("Registration failed");
    }

    // Verify metrics
    ctx.record_metric(
        "model_registration.duration_ms",
        start_time.elapsed().as_millis() as f64,
        None,
    ).await;

    Ok(())
}

/// Tests inference engine performance and accuracy requirements
#[tokio::test]
#[criterion]
async fn test_inference_performance() -> Result<(), GuardianError> {
    let ctx = setup_test_environment().await?;
    let mut total_latency = 0.0;
    let mut total_accuracy = 0.0;
    let mut total_memory = 0.0;
    let iterations = 100;

    // Generate test security events
    let mut test_events = Vec::new();
    for _ in 0..TEST_BATCH_SIZE {
        test_events.push(SecurityEvent {
            event_type: "test".to_string(),
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            data: HashMap::new(),
        });
    }

    // Warm-up phase
    for _ in 0..10 {
        let _ = ctx.inference_engine.batch_predict(test_events.clone()).await?;
    }

    // Performance testing
    for i in 0..iterations {
        let start = Instant::now();
        let predictions = ctx.inference_engine.batch_predict(test_events.clone()).await?;
        let latency = start.elapsed().as_millis() as f64;

        // Verify performance requirements
        assert!(latency < PERFORMANCE_THRESHOLD_MS as f64, 
            "Inference latency exceeded threshold: {}ms", latency);

        // Calculate accuracy
        let accuracy = predictions.iter()
            .filter(|p| p.confidence >= 0.95)
            .count() as f64 / predictions.len() as f64;
        assert!(accuracy >= ACCURACY_THRESHOLD,
            "Accuracy below threshold: {}", accuracy);

        // Monitor resource usage
        let memory_usage = ctx.metrics_collector
            .get_metric("guardian.ml.memory_usage")
            .await
            .unwrap_or(0.0);
        assert!(memory_usage <= RESOURCE_USAGE_THRESHOLD,
            "Memory usage exceeded threshold: {}", memory_usage);

        total_latency += latency;
        total_accuracy += accuracy;
        total_memory += memory_usage;

        // Record metrics
        ctx.record_metric(
            "inference.latency_ms",
            latency,
            Some(HashMap::from([("iteration".to_string(), i.to_string())])),
        ).await;
    }

    // Record aggregate metrics
    ctx.record_metric(
        "inference.avg_latency_ms",
        total_latency / iterations as f64,
        None,
    ).await;
    ctx.record_metric(
        "inference.avg_accuracy",
        total_accuracy / iterations as f64,
        None,
    ).await;
    ctx.record_metric(
        "inference.avg_memory_usage",
        total_memory / iterations as f64,
        None,
    ).await;

    Ok(())
}

criterion_group!(benches, test_inference_performance);
criterion_main!(benches);