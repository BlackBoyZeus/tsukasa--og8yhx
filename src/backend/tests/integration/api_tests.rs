use std::{sync::Arc, time::Duration};
use tokio::time;
use tonic::{Request, Response, Status};
use mockall::predicate::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use metrics::{counter, gauge, histogram};

use crate::api::grpc::{
    GuardianService,
    GuardianSecurityService,
    guardian_proto::{SystemStatus, Event, SecurityResponse},
};
use crate::api::ApiConfig;
use crate::utils::error::GuardianError;

// Test constants
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_CERT_PATH: &str = "test/certs/test.pem";
const PERFORMANCE_THRESHOLD: Duration = Duration::from_millis(100);
const RESOURCE_LIMIT: f64 = 5.0;

/// Enhanced test context with metrics and service discovery
#[derive(Debug)]
struct TestContext {
    guardian_service: Arc<GuardianService>,
    security_service: Arc<GuardianSecurityService>,
    api_config: ApiConfig,
    metrics_collector: Arc<metrics::MetricsCollector>,
    circuit_breaker: Arc<CircuitBreaker>,
    service_discovery: Arc<ServiceDiscovery>,
    health_checker: Arc<HealthChecker>,
}

impl TestContext {
    /// Creates a new test context with monitoring
    async fn new(config: TestConfig) -> Result<Self, GuardianError> {
        // Initialize metrics collector
        let metrics_collector = Arc::new(metrics::MetricsCollector::new(
            metrics::MetricsConfig {
                statsd_host: "localhost".into(),
                statsd_port: 8125,
                buffer_size: Some(1000),
                flush_interval: Some(Duration::from_secs(1)),
                sampling_rates: None,
            },
        )?);

        // Initialize circuit breaker
        let circuit_breaker = Arc::new(CircuitBreaker::new(5));

        // Initialize service discovery
        let service_discovery = Arc::new(ServiceDiscovery::new(
            "guardian",
            vec!["guardian-service", "security-service"],
        ));

        // Initialize health checker
        let health_checker = Arc::new(HealthChecker::new(
            Duration::from_secs(5),
            metrics_collector.clone(),
        ));

        // Initialize services
        let guardian_service = Arc::new(GuardianService::new(
            Arc::new(Guardian::new(GuardianConfig::default()).await?),
            Arc::new(RwLock::new(SystemState::default())),
        )?);

        let security_service = Arc::new(GuardianSecurityService::new(
            Arc::new(ThreatDetector::new(
                Arc::new(InferenceEngine::new(
                    Arc::new(ModelRegistry::new(
                        Arc::new(ModelStore::new(
                            Arc::new(ZfsManager::new(
                                "testpool".to_string(),
                                vec![0u8; 32],
                                Arc::new(LogManager::new()),
                                None,
                            ).await?),
                            std::path::PathBuf::from("/tmp/test_models"),
                            Some(5),
                        ).await?),
                    ).await?),
                ).await?),
            )),
            Arc::new(ResponseEngine::new(
                Arc::new(temporal_sdk::Client::new(
                    temporal_sdk::ConnectionOptions::default(),
                ).await?),
                Arc::new(EventBus::new(
                    CoreMetricsManager::new(
                        metrics_collector.clone(),
                        MetricsConfig::default(),
                    )?,
                )?),
                None,
            ).await?),
            SecurityServiceConfig::default(),
        ));

        Ok(Self {
            guardian_service,
            security_service,
            api_config: ApiConfig::default(),
            metrics_collector,
            circuit_breaker,
            service_discovery,
            health_checker,
        })
    }

    /// Comprehensive cleanup of test resources and metrics
    async fn cleanup(&self) -> Result<(), GuardianError> {
        // Stop services
        self.guardian_service.shutdown().await?;
        self.security_service.shutdown().await?;

        // Clear metrics
        self.metrics_collector.flush().await?;

        // Stop health checks
        self.health_checker.stop().await;

        // Cleanup service discovery
        self.service_discovery.cleanup().await?;

        Ok(())
    }
}

/// Sets up the test environment with mock services and monitoring
#[tokio::test]
async fn setup_test_environment() -> Result<TestContext, GuardianError> {
    let config = TestConfig {
        enable_metrics: true,
        enable_security: true,
        enable_service_discovery: true,
    };

    let context = TestContext::new(config).await?;

    // Verify services are healthy
    assert!(context.guardian_service.health_check().await.is_ok());
    assert!(context.security_service.health_check().await.is_ok());

    // Verify metrics are collecting
    assert!(context.metrics_collector.is_healthy());

    // Verify service discovery
    assert!(context.service_discovery.is_ready().await);

    Ok(context)
}

/// Tests the Guardian service status endpoint with performance validation
#[tokio::test]
async fn test_guardian_service_status() -> Result<(), GuardianError> {
    let context = setup_test_environment().await?;

    // Create request with mTLS
    let request = Request::new(guardian_proto::Empty {});
    let request = request.with_tls_identity(tonic::transport::Identity::from_pem(
        include_bytes!(TEST_CERT_PATH),
        include_bytes!(TEST_CERT_PATH),
    ));

    // Measure response time
    let start = time::Instant::now();
    let response = context.guardian_service.get_system_status(request).await?;
    let duration = start.elapsed();

    // Validate response
    let status = response.into_inner();
    assert!(status.cpu_usage >= 0.0 && status.cpu_usage <= 100.0);
    assert!(status.memory_usage >= 0.0 && status.memory_usage <= 100.0);
    assert!(status.active_threats >= 0);

    // Verify performance
    assert!(duration <= PERFORMANCE_THRESHOLD);
    histogram!("test.guardian.status.latency", duration.as_secs_f64());

    // Verify resource usage
    let metrics = context.metrics_collector.collect_metrics(None).await?;
    assert!(metrics.iter().any(|m| m.name == "guardian.service.cpu_usage" && m.value <= RESOURCE_LIMIT));

    context.cleanup().await?;
    Ok(())
}

/// Tests security service threat detection with circuit breaker
#[tokio::test]
async fn test_security_service_threat_detection() -> Result<(), GuardianError> {
    let context = setup_test_environment().await?;

    // Create request
    let request = Request::new(guardian_proto::Empty {});

    // Test circuit breaker
    for _ in 0..10 {
        let result = context.security_service.detect_threats(request.clone()).await;
        if context.circuit_breaker.is_open() {
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().code(),
                tonic::Code::Unavailable
            );
            break;
        }
    }

    // Verify metrics
    let metrics = context.metrics_collector.collect_metrics(None).await?;
    assert!(metrics.iter().any(|m| m.name == "guardian.security.circuit_breaker.trips"));

    context.cleanup().await?;
    Ok(())
}

/// Tests service discovery and health checks
#[tokio::test]
async fn test_service_discovery() -> Result<(), GuardianError> {
    let context = setup_test_environment().await?;

    // Register services
    context.service_discovery.register_service(
        "guardian-test",
        "localhost",
        50051,
    ).await?;

    // Verify service discovery
    let services = context.service_discovery.list_services().await?;
    assert!(services.contains(&"guardian-test".to_string()));

    // Test health checks
    let health_status = context.health_checker.check_service("guardian-test").await?;
    assert!(health_status.is_healthy);

    context.cleanup().await?;
    Ok(())
}

/// Performance benchmarks for API endpoints
fn criterion_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let context = rt.block_on(setup_test_environment()).unwrap();

    c.bench_function("guardian_status", |b| {
        b.iter(|| {
            rt.block_on(async {
                let request = Request::new(guardian_proto::Empty {});
                black_box(context.guardian_service.get_system_status(request).await.unwrap());
            })
        })
    });

    rt.block_on(context.cleanup()).unwrap();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);