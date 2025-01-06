use std::time::Duration;
use tokio::time::timeout;
use tonic::{Request, Response, Status};
use mockall::predicate::*;
use test_context::{AsyncTestContext, test_context};
use tracing::{info, error};

use crate::api::grpc::{
    guardian_service::GuardianService,
    security_service::SecurityService,
    init_grpc_server,
};
use crate::api::{initialize_api, APIConfig};
use crate::utils::error::GuardianError;

// Test constants
const TEST_GRPC_PORT: u16 = 50052;
const TEST_TIMEOUT_MS: u64 = 5000;
const PERFORMANCE_THRESHOLD_MS: u64 = 100;
const RESOURCE_USAGE_LIMIT_PERCENT: f32 = 5.0;
const ERROR_RETRY_COUNT: u32 = 3;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Enhanced test context for API integration tests
#[derive(Debug)]
struct ApiTestContext {
    server: TestServer,
    client: GrpcClient,
    metrics: MetricsCollector,
    security_validator: SecurityValidator,
    resource_monitor: ResourceMonitor,
}

impl ApiTestContext {
    /// Creates new test context with enhanced monitoring
    async fn new(config: TestConfig) -> Result<Self, GuardianError> {
        // Initialize test server with monitoring
        let server = setup_test_server(config).await?;
        
        // Initialize gRPC client with timeout handling
        let client = GrpcClient::connect(format!("http://[::1]:{}", TEST_GRPC_PORT))
            .await
            .map_err(|e| GuardianError::SystemError(format!("Failed to connect to test server: {}", e)))?;

        // Initialize metrics collection
        let metrics = MetricsCollector::new();
        
        // Initialize security validation
        let security_validator = SecurityValidator::new();
        
        // Initialize resource monitoring
        let resource_monitor = ResourceMonitor::new(RESOURCE_USAGE_LIMIT_PERCENT);

        Ok(Self {
            server,
            client,
            metrics,
            security_validator,
            resource_monitor,
        })
    }

    /// Tests Guardian service status endpoint with performance validation
    async fn test_guardian_status(&self) -> Result<(), GuardianError> {
        let start = std::time::Instant::now();

        // Send status request with timeout
        let response = timeout(
            Duration::from_millis(TEST_TIMEOUT_MS),
            self.client.get_system_status(Request::new(Empty {}))
        ).await.map_err(|_| GuardianError::SystemError("Request timeout".to_string()))??;

        // Verify response latency
        let duration = start.elapsed();
        assert!(
            duration.as_millis() < PERFORMANCE_THRESHOLD_MS as u128,
            "Response latency {} exceeds threshold {}",
            duration.as_millis(),
            PERFORMANCE_THRESHOLD_MS
        );

        // Validate metrics within thresholds
        self.metrics.validate_metrics()?;

        // Check resource usage
        self.resource_monitor.check_usage()?;

        // Verify security controls
        self.security_validator.validate_response(&response)?;

        Ok(())
    }

    /// Tests security monitoring stream with threat simulation
    async fn test_security_monitoring(&self) -> Result<(), GuardianError> {
        // Initialize monitoring stream with timeout
        let mut stream = self.client.monitor_metrics(Request::new(Empty {}))
            .await?
            .into_inner();

        // Inject test threats with varying severity
        let test_threats = generate_test_threats();
        for threat in test_threats {
            self.client.simulate_threat(threat).await?;
        }

        // Verify alert generation time
        let start = std::time::Instant::now();
        while let Some(alert) = stream.message().await? {
            assert!(
                start.elapsed().as_millis() < TEST_TIMEOUT_MS as u128,
                "Alert generation exceeded timeout"
            );
            
            // Validate response actions
            self.security_validator.validate_alert(&alert)?;
        }

        // Check security policy compliance
        self.security_validator.verify_compliance()?;

        // Verify resource usage during threat response
        self.resource_monitor.check_usage()?;

        Ok(())
    }

    /// Tests API error handling and circuit breaker functionality
    async fn test_error_handling(&self) -> Result<(), GuardianError> {
        // Simulate various error conditions
        let error_cases = generate_error_cases();
        let mut failures = 0;

        for error_case in error_cases {
            match self.client.trigger_error(error_case).await {
                Ok(_) => continue,
                Err(e) => {
                    failures += 1;
                    error!("Error case failed: {}", e);

                    // Verify retry behavior
                    if failures < ERROR_RETRY_COUNT {
                        continue;
                    }

                    // Test circuit breaker activation
                    if failures >= CIRCUIT_BREAKER_THRESHOLD {
                        assert!(
                            matches!(e, Status::Unavailable(_)),
                            "Circuit breaker should be open"
                        );
                        break;
                    }
                }
            }
        }

        // Validate error responses
        self.security_validator.verify_error_handling(failures)?;

        // Check error logging
        self.metrics.verify_error_metrics(failures)?;

        // Verify system stability during errors
        self.resource_monitor.check_usage()?;

        Ok(())
    }
}

#[async_trait]
impl AsyncTestContext for ApiTestContext {
    async fn setup() -> Self {
        let config = TestConfig {
            port: TEST_GRPC_PORT,
            timeout: Duration::from_millis(TEST_TIMEOUT_MS),
        };
        Self::new(config).await.expect("Failed to setup test context")
    }

    async fn teardown(self) {
        if let Err(e) = cleanup_test_resources(self.server).await {
            error!("Failed to cleanup test resources: {}", e);
        }
    }
}

/// Sets up a test gRPC server instance with mock services
async fn setup_test_server(config: TestConfig) -> Result<TestServer, GuardianError> {
    // Initialize test configuration and metrics
    let api_config = APIConfig {
        grpc_port: config.port,
        request_timeout: config.timeout,
        ..Default::default()
    };

    // Create mock services with performance monitoring
    let guardian_service = Arc::new(GuardianService::new(
        Arc::new(MockGuardian::new())
    ));

    let security_service = Arc::new(SecurityService::new(
        Arc::new(MockThreatDetector::new()),
        Arc::new(MockResponseEngine::new())
    ));

    // Initialize server with metrics collection
    let server = init_grpc_server(api_config).await?;

    Ok(TestServer {
        server,
        guardian_service,
        security_service,
    })
}

/// Cleans up test resources and validates resource usage
async fn cleanup_test_resources(server: TestServer) -> Result<(), GuardianError> {
    // Stop test server
    server.shutdown().await?;

    // Cleanup mock resources
    server.guardian_service.cleanup().await?;
    server.security_service.cleanup().await?;

    // Validate resource usage metrics
    let metrics = server.get_metrics().await?;
    assert!(
        metrics.resource_usage < RESOURCE_USAGE_LIMIT_PERCENT,
        "Resource usage exceeded limit during test"
    );

    // Reset monitoring state
    metrics.reset().await?;

    // Clear test data
    server.clear_test_data().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_context(ApiTestContext)]
    #[tokio::test]
    async fn test_guardian_api_status(ctx: &mut ApiTestContext) {
        ctx.test_guardian_status().await.expect("Status test failed");
    }

    #[test_context(ApiTestContext)]
    #[tokio::test]
    async fn test_security_monitoring(ctx: &mut ApiTestContext) {
        ctx.test_security_monitoring().await.expect("Security monitoring test failed");
    }

    #[test_context(ApiTestContext)]
    #[tokio::test]
    async fn test_error_handling(ctx: &mut ApiTestContext) {
        ctx.test_error_handling().await.expect("Error handling test failed");
    }
}