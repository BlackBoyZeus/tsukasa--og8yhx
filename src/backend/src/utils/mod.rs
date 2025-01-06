//! Guardian system utility module providing centralized access to common functionality
//! Version: 1.0.0
//! Security: High - Implements strict security boundaries and resource optimization

use std::sync::Once;
use std::time::Duration;

// Re-export core types and functionality from submodules
pub use error::{ErrorContext, GuardianError, Result};
pub use logging::{init_logging, LogConfig};
pub use metrics::{MetricPriority, MetricType, MetricsCollector};
pub use validation::{ValidationContext, ValidationError, ValidationResult};

// Internal module declarations
mod error;
mod logging;
mod metrics;
mod validation;

// Create a prelude module for commonly used types
pub mod prelude {
    pub use super::error::{GuardianError, Result};
    pub use super::metrics::MetricType;
    pub use super::validation::ValidationResult;
}

// Constants for utility configuration
const DEFAULT_INIT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRY_ATTEMPTS: u32 = 3;
static INIT_GUARD: Once = Once::new();

/// Configuration for utility subsystems
#[derive(Debug, Clone)]
pub struct UtilsConfig {
    /// Logging configuration
    pub log_config: LogConfig,
    /// Metrics collection settings
    pub metrics_config: metrics::MetricsConfig,
    /// Resource limits and thresholds
    pub resource_limits: ResourceLimits,
}

/// Resource limits and thresholds for utility operations
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum memory usage for utilities (in bytes)
    pub max_memory: usize,
    /// Maximum CPU usage percentage
    pub max_cpu_percent: f64,
    /// I/O operation limits
    pub max_io_ops: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory: 100 * 1024 * 1024, // 100MB
            max_cpu_percent: 5.0,           // 5% CPU usage
            max_io_ops: 1000,              // 1000 ops/sec
        }
    }
}

/// Initializes all utility subsystems with proper ordering and security checks
#[tracing::instrument(skip(config))]
pub async fn init_utils(config: UtilsConfig) -> Result<()> {
    let mut result = Ok(());
    
    INIT_GUARD.call_once(|| {
        // Initialize logging first for proper diagnostics
        if let Err(e) = init_logging(config.log_config.clone()) {
            result = Err(e);
            return;
        }

        // Initialize metrics collection
        let metrics_collector = match MetricsCollector::new(config.metrics_config) {
            Ok(collector) => collector,
            Err(e) => {
                result = Err(e);
                return;
            }
        };

        // Record initialization metrics
        if let Err(e) = metrics_collector.record_metric(
            "guardian.utils.initialization".into(),
            1.0,
            MetricType::Counter,
            MetricPriority::High,
            None,
        ) {
            result = Err(e);
            return;
        }

        // Verify resource limits
        if let Err(e) = verify_resource_limits(&config.resource_limits) {
            result = Err(e);
            return;
        }
    });

    result
}

/// Verifies system resource limits and availability
#[tracing::instrument]
fn verify_resource_limits(limits: &ResourceLimits) -> Result<()> {
    // Check available memory
    let memory_info = sys_info::mem_info().map_err(|e| GuardianError::SystemError {
        context: "Failed to get memory info".into(),
        source: Some(Box::new(e)),
        severity: error::ErrorSeverity::High,
        timestamp: time::OffsetDateTime::now_utc(),
        correlation_id: uuid::Uuid::new_v4(),
        category: error::ErrorCategory::System,
        retry_count: 0,
    })?;

    if memory_info.avail as usize <= limits.max_memory {
        return Err(GuardianError::SystemError {
            context: "Insufficient memory available".into(),
            source: None,
            severity: error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: error::ErrorCategory::System,
            retry_count: 0,
        });
    }

    // Check CPU usage
    let cpu_info = sys_info::loadavg().map_err(|e| GuardianError::SystemError {
        context: "Failed to get CPU info".into(),
        source: Some(Box::new(e)),
        severity: error::ErrorSeverity::High,
        timestamp: time::OffsetDateTime::now_utc(),
        correlation_id: uuid::Uuid::new_v4(),
        category: error::ErrorCategory::System,
        retry_count: 0,
    })?;

    if cpu_info.one > limits.max_cpu_percent {
        return Err(GuardianError::SystemError {
            context: "CPU usage exceeds limit".into(),
            source: None,
            severity: error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: error::ErrorCategory::System,
            retry_count: 0,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_utils_initialization() {
        let config = UtilsConfig {
            log_config: LogConfig::default(),
            metrics_config: metrics::MetricsConfig {
                statsd_host: "localhost".into(),
                statsd_port: 8125,
                buffer_size: Some(1000),
                flush_interval: Some(Duration::from_secs(10)),
                sampling_rates: None,
            },
            resource_limits: ResourceLimits::default(),
        };

        let result = init_utils(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_resource_limits_verification() {
        let limits = ResourceLimits::default();
        let result = verify_resource_limits(&limits);
        assert!(result.is_ok());
    }
}