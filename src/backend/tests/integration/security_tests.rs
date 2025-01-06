use std::{sync::Arc, time::Duration};
use tokio::time;
use criterion::{criterion_group, criterion_main, Criterion};
use test_context::{AsyncTestContext, test_context};
use tracing::{info, error};

use guardian::security::{SecurityManager, SecurityMetrics};
use guardian::utils::error::{GuardianError, ErrorCategory, ErrorSeverity};
use guardian::utils::metrics::{MetricsCollector, MetricType, MetricPriority};
use guardian::config::security_config::SecurityConfig;
use guardian::utils::validation::ValidationContext;

// Test constants aligned with SLAs
const SECURITY_TEST_TIMEOUT: Duration = Duration::from_secs(60);
const THREAT_DETECTION_SLA: Duration = Duration::from_millis(100);
const REQUIRED_DETECTION_ACCURACY: f64 = 0.99999;
const TEST_ITERATIONS: u32 = 1000;
const PERFORMANCE_SAMPLE_SIZE: usize = 100;

/// Enhanced test harness for security integration testing
#[derive(Debug)]
struct SecurityTestHarness {
    security_manager: Arc<SecurityManager>,
    metrics_collector: Arc<MetricsCollector>,
    validation_context: ValidationContext,
    start_time: std::time::Instant,
}

impl SecurityTestHarness {
    async fn new() -> Result<Self, GuardianError> {
        let config = SecurityConfig::new();
        let metrics_collector = Arc::new(MetricsCollector::new(Default::default())?);
        let security_manager = SecurityManager::new(config, Arc::clone(&metrics_collector))?;
        
        security_manager.initialize().await?;

        Ok(Self {
            security_manager: Arc::new(security_manager),
            metrics_collector,
            validation_context: ValidationContext::new(MetricsCollector::new(Default::default())?),
            start_time: std::time::Instant::now(),
        })
    }

    async fn validate_security_metrics(&self) -> Result<SecurityMetrics, GuardianError> {
        self.security_manager.get_security_metrics().await
    }
}

#[tokio::test]
async fn test_security_initialization() -> Result<(), GuardianError> {
    let harness = SecurityTestHarness::new().await?;
    let metrics = harness.validate_security_metrics().await?;

    assert!(metrics.avg_detection_time_ms < THREAT_DETECTION_SLA.as_millis() as u64);
    assert_eq!(metrics.circuit_breaker_failures, 0);
    
    Ok(())
}

#[tokio::test]
#[criterion]
async fn test_threat_detection_performance() -> Result<(), GuardianError> {
    let harness = SecurityTestHarness::new().await?;
    let mut detection_times = Vec::with_capacity(PERFORMANCE_SAMPLE_SIZE);

    for _ in 0..PERFORMANCE_SAMPLE_SIZE {
        let start = std::time::Instant::now();
        
        // Simulate threat detection workload
        harness.security_manager.initialize().await?;
        let metrics = harness.validate_security_metrics().await?;
        
        detection_times.push(start.elapsed().as_millis() as f64);
        
        // Validate against SLA
        assert!(metrics.avg_detection_time_ms < THREAT_DETECTION_SLA.as_millis() as u64);
    }

    // Calculate performance statistics
    let avg_detection_time = detection_times.iter().sum::<f64>() / detection_times.len() as f64;
    let max_detection_time = detection_times.iter().fold(0f64, |max, &x| max.max(x));

    harness.metrics_collector.record_metric(
        "security.test.avg_detection_time".into(),
        avg_detection_time,
        MetricType::Histogram,
        MetricPriority::Critical,
        None,
    )?;

    assert!(avg_detection_time < THREAT_DETECTION_SLA.as_millis() as f64);
    assert!(max_detection_time < THREAT_DETECTION_SLA.as_millis() as f64 * 1.5);

    Ok(())
}

#[tokio::test]
async fn test_encryption_standards() -> Result<(), GuardianError> {
    let harness = SecurityTestHarness::new().await?;
    let test_data = "sensitive_test_data";
    
    // Test AES-256-GCM encryption
    let encrypted = harness.security_manager.crypto_manager.encrypt(test_data.as_bytes())?;
    let decrypted = harness.security_manager.crypto_manager.decrypt(&encrypted)?;
    
    assert_eq!(test_data.as_bytes(), decrypted.as_slice());
    
    // Validate TLS 1.3 configuration
    let config = harness.security_manager.config.clone();
    assert_eq!(config.tls_version, "1.3");
    assert!(config.cipher_suites.contains(&"TLS_AES_256_GCM_SHA384".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_audit_logging() -> Result<(), GuardianError> {
    let harness = SecurityTestHarness::new().await?;
    
    // Generate test security events
    for i in 0..TEST_ITERATIONS {
        harness.security_manager.audit_manager.log_security_event(
            format!("Test security event {}", i),
            ErrorSeverity::High,
            ErrorCategory::Security,
        ).await?;
    }

    // Validate audit log integrity
    let audit_logs = harness.security_manager.audit_manager.get_audit_logs().await?;
    assert_eq!(audit_logs.len(), TEST_ITERATIONS as usize);
    
    // Verify log retention
    let oldest_log = audit_logs.first().unwrap();
    assert!(oldest_log.timestamp <= time::OffsetDateTime::now_utc());

    Ok(())
}

#[tokio::test]
async fn test_security_validation() -> Result<(), GuardianError> {
    let harness = SecurityTestHarness::new().await?;
    let mut successful_validations = 0;

    // Run security validation tests
    for _ in 0..TEST_ITERATIONS {
        let result = harness.validation_context.validate("test_input")?;
        if result.is_valid {
            successful_validations += 1;
        }
    }

    // Calculate validation accuracy
    let accuracy = successful_validations as f64 / TEST_ITERATIONS as f64;
    
    harness.metrics_collector.record_metric(
        "security.test.validation_accuracy".into(),
        accuracy,
        MetricType::Gauge,
        MetricPriority::Critical,
        None,
    )?;

    assert!(accuracy >= REQUIRED_DETECTION_ACCURACY);

    Ok(())
}

#[tokio::test]
async fn test_security_circuit_breaker() -> Result<(), GuardianError> {
    let harness = SecurityTestHarness::new().await?;
    
    // Test circuit breaker under load
    for _ in 0..TEST_ITERATIONS {
        let metrics = harness.validate_security_metrics().await?;
        assert!(metrics.circuit_breaker_failures < 3, "Circuit breaker triggered unexpectedly");
        
        // Small delay to prevent overwhelming the system
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    Ok(())
}

criterion_group!(
    name = security_benches;
    config = Criterion::default().sample_size(PERFORMANCE_SAMPLE_SIZE);
    targets = test_threat_detection_performance
);
criterion_main!(security_benches);

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_harness_initialization() {
        let harness = SecurityTestHarness::new().await.unwrap();
        assert!(harness.start_time.elapsed() < SECURITY_TEST_TIMEOUT);
    }
}