use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use crate::utils::error::{GuardianError, SecurityError, ConfigError};
use crate::utils::metrics::Metrics;
use crate::config::security_config::SecurityConfig;

// Version and performance constants
const SECURITY_VERSION: &str = "1.0.0";
const MAX_DETECTION_TIME_MS: u64 = 100;
const SECURITY_METRICS_INTERVAL_MS: u64 = 1000;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 3;

// Re-export security submodules
pub mod crypto;
pub mod audit;
pub mod threat_detection;

use crypto::CryptoManager;
use audit::AuditManager;
use threat_detection::ThreatDetector;

/// Coordinates all security-related functionality with performance optimization and monitoring
#[derive(Debug)]
pub struct SecurityManager {
    crypto_manager: Arc<CryptoManager>,
    audit_manager: Arc<AuditManager>,
    threat_detector: Arc<ThreatDetector>,
    config: SecurityConfig,
    metrics: Arc<Metrics>,
    performance_monitor: Arc<RwLock<PerformanceMonitor>>,
}

#[derive(Debug)]
struct PerformanceMonitor {
    detection_times: Vec<u64>,
    circuit_breaker_failures: u32,
    last_reset: std::time::Instant,
}

impl SecurityManager {
    /// Creates a new SecurityManager instance with performance monitoring
    #[instrument(skip(config, metrics))]
    pub fn new(config: SecurityConfig, metrics: Arc<Metrics>) -> Result<Arc<Self>, GuardianError> {
        // Validate security configuration with performance limits
        config.validate().map_err(|e| GuardianError::ConfigError {
            context: "Failed to validate security configuration".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        // Initialize core security components
        let crypto_manager = CryptoManager::new(&config)?;
        let audit_manager = AuditManager::new(&config)?;
        let threat_detector = ThreatDetector::new(&config)?;

        let performance_monitor = Arc::new(RwLock::new(PerformanceMonitor {
            detection_times: Vec::with_capacity(1000),
            circuit_breaker_failures: 0,
            last_reset: std::time::Instant::now(),
        }));

        let manager = Arc::new(Self {
            crypto_manager: Arc::new(crypto_manager),
            audit_manager: Arc::new(audit_manager),
            threat_detector: Arc::new(threat_detector),
            config,
            metrics,
            performance_monitor,
        });

        // Start performance monitoring
        Self::start_performance_monitoring(Arc::clone(&manager));

        info!("SecurityManager initialized successfully");
        Ok(manager)
    }

    /// Initializes the security subsystem with performance monitoring
    #[instrument(skip(self))]
    pub async fn initialize(&self) -> Result<(), GuardianError> {
        let start = std::time::Instant::now();

        // Initialize cryptographic services with performance monitoring
        self.crypto_manager.initialize().await.map_err(|e| GuardianError::SecurityError {
            context: "Failed to initialize crypto manager".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        // Start enhanced audit logging
        self.audit_manager.initialize().await.map_err(|e| GuardianError::SecurityError {
            context: "Failed to initialize audit manager".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        // Begin optimized threat detection
        self.threat_detector.initialize().await.map_err(|e| GuardianError::SecurityError {
            context: "Failed to initialize threat detector".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        let init_time = start.elapsed().as_millis() as f64;
        self.metrics.record_security_metric("security.initialization.time", init_time);

        info!("Security subsystem initialized in {}ms", init_time);
        Ok(())
    }

    /// Retrieves current security metrics and performance data
    #[instrument(skip(self))]
    pub async fn get_security_metrics(&self) -> Result<SecurityMetrics, GuardianError> {
        let monitor = self.performance_monitor.read().await;
        let avg_detection_time = if !monitor.detection_times.is_empty() {
            monitor.detection_times.iter().sum::<u64>() / monitor.detection_times.len() as u64
        } else {
            0
        };

        Ok(SecurityMetrics {
            avg_detection_time_ms: avg_detection_time,
            circuit_breaker_failures: monitor.circuit_breaker_failures,
            crypto_status: self.crypto_manager.get_status().await?,
            audit_status: self.audit_manager.get_status().await?,
            threat_status: self.threat_detector.get_status().await?,
        })
    }

    // Private helper methods
    fn start_performance_monitoring(manager: Arc<SecurityManager>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_millis(SECURITY_METRICS_INTERVAL_MS)
            );

            loop {
                interval.tick().await;
                if let Err(e) = manager.monitor_performance().await {
                    error!("Performance monitoring error: {:?}", e);
                }
            }
        });
    }

    #[instrument(skip(self))]
    async fn monitor_performance(&self) -> Result<(), GuardianError> {
        let mut monitor = self.performance_monitor.write().await;

        // Reset metrics periodically
        if monitor.last_reset.elapsed() > std::time::Duration::from_secs(3600) {
            monitor.detection_times.clear();
            monitor.circuit_breaker_failures = 0;
            monitor.last_reset = std::time::Instant::now();
        }

        // Check performance thresholds
        if let Some(avg_time) = monitor.detection_times.last() {
            if *avg_time > MAX_DETECTION_TIME_MS {
                warn!("Detection time exceeded threshold: {}ms", avg_time);
                monitor.circuit_breaker_failures += 1;

                if monitor.circuit_breaker_failures >= CIRCUIT_BREAKER_THRESHOLD {
                    error!("Circuit breaker triggered due to performance degradation");
                    self.metrics.record_security_metric("security.circuit_breaker.triggered", 1.0);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct SecurityMetrics {
    avg_detection_time_ms: u64,
    circuit_breaker_failures: u32,
    crypto_status: crypto::CryptoStatus,
    audit_status: audit::AuditStatus,
    threat_status: threat_detection::ThreatStatus,
}

/// Verifies the overall security state and performance of the system
#[instrument]
pub async fn verify_security_state(security_manager: &SecurityManager) -> Result<SecurityStatus, GuardianError> {
    let metrics = security_manager.get_security_metrics().await?;
    
    // Validate performance metrics
    if metrics.avg_detection_time_ms > MAX_DETECTION_TIME_MS {
        return Err(GuardianError::SecurityError {
            context: format!("Detection time exceeds threshold: {}ms", metrics.avg_detection_time_ms),
            source: None,
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        });
    }

    Ok(SecurityStatus {
        is_healthy: metrics.circuit_breaker_failures < CIRCUIT_BREAKER_THRESHOLD,
        metrics,
        timestamp: time::OffsetDateTime::now_utc(),
    })
}

#[derive(Debug)]
pub struct SecurityStatus {
    pub is_healthy: bool,
    pub metrics: SecurityMetrics,
    pub timestamp: time::OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_security_manager_initialization() {
        let config = SecurityConfig::default();
        let metrics = Arc::new(Metrics::new().unwrap());
        
        let manager = SecurityManager::new(config, metrics).unwrap();
        assert!(manager.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_performance_monitoring() {
        let config = SecurityConfig::default();
        let metrics = Arc::new(Metrics::new().unwrap());
        
        let manager = SecurityManager::new(config, metrics).unwrap();
        let metrics = manager.get_security_metrics().await.unwrap();
        
        assert!(metrics.avg_detection_time_ms <= MAX_DETECTION_TIME_MS);
        assert_eq!(metrics.circuit_breaker_failures, 0);
    }
}