use async_trait::async_trait;
use metrics::{counter, gauge, histogram};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use temporal_sdk::{ActivityOptions, ActivityResult};
use tokio::time;
use tracing::{debug, error, info, instrument, warn};

use crate::core::metrics::CoreMetricsManager;
use crate::core::system_state::{SystemHealth, SystemState};
use crate::utils::error::{GuardianError, ErrorSeverity, ErrorCategory};

// Constants for monitoring configuration
const METRICS_COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(15);
const RESOURCE_MONITOR_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_ACTIVITY_RETRIES: u32 = 3;
const MIN_SAMPLING_INTERVAL: Duration = Duration::from_millis(100);
const MAX_OVERHEAD_PERCENTAGE: f64 = 5.0;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Configuration for adaptive sampling
#[derive(Debug, Clone)]
struct SamplingConfig {
    base_interval: Duration,
    min_interval: Duration,
    max_interval: Duration,
    overhead_threshold: f64,
}

/// Circuit breaker for monitoring activities
#[derive(Debug, Clone)]
struct CircuitBreaker {
    failures: u32,
    last_failure: Instant,
    is_open: bool,
}

/// Snapshot of collected metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub system_load: f64,
    pub collection_overhead: f64,
    pub timestamp: time::OffsetDateTime,
}

/// Resource usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_utilization: f64,
    pub memory_consumption: f64,
    pub io_operations: u64,
    pub monitoring_overhead: f64,
    pub timestamp: time::OffsetDateTime,
}

/// Core monitoring activities implementation
#[derive(Debug)]
pub struct MonitoringActivities {
    metrics_manager: CoreMetricsManager,
    system_state: Arc<parking_lot::RwLock<SystemState>>,
    circuit_breaker: CircuitBreaker,
    sampling_config: SamplingConfig,
}

#[async_trait]
impl MonitoringActivities {
    /// Creates a new MonitoringActivities instance
    pub fn new(
        metrics_manager: CoreMetricsManager,
        system_state: Arc<parking_lot::RwLock<SystemState>>,
        circuit_breaker_config: Option<CircuitBreaker>,
        sampling_config: Option<SamplingConfig>,
    ) -> Self {
        Self {
            metrics_manager,
            system_state,
            circuit_breaker: circuit_breaker_config.unwrap_or(CircuitBreaker {
                failures: 0,
                last_failure: Instant::now(),
                is_open: false,
            }),
            sampling_config: sampling_config.unwrap_or(SamplingConfig {
                base_interval: Duration::from_secs(1),
                min_interval: MIN_SAMPLING_INTERVAL,
                max_interval: Duration::from_secs(5),
                overhead_threshold: MAX_OVERHEAD_PERCENTAGE,
            }),
        }
    }

    /// Collects system-wide metrics with adaptive sampling
    #[instrument(skip(self))]
    #[activity(retry_policy = "exponential_backoff")]
    pub async fn collect_system_metrics(&self) -> ActivityResult<MetricsSnapshot> {
        if self.circuit_breaker.is_open {
            return Err(GuardianError::SystemError {
                context: "Circuit breaker is open for metrics collection".into(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::System,
                retry_count: 0,
            }.into());
        }

        let start_time = Instant::now();
        let mut snapshot = MetricsSnapshot {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            system_load: 0.0,
            collection_overhead: 0.0,
            timestamp: time::OffsetDateTime::now_utc(),
        };

        // Collect CPU metrics with priority
        self.metrics_manager.record_system_metric(
            "cpu.usage".into(),
            snapshot.cpu_usage,
            Some(crate::core::metrics::Priority::High),
        ).await?;

        // Collect memory metrics with sampling
        self.metrics_manager.record_system_metric(
            "memory.usage".into(),
            snapshot.memory_usage,
            Some(crate::core::metrics::Priority::High),
        ).await?;

        // Calculate collection overhead
        let elapsed = start_time.elapsed();
        snapshot.collection_overhead = (elapsed.as_secs_f64() / self.sampling_config.base_interval.as_secs_f64()) * 100.0;

        // Adjust sampling rate based on overhead
        if snapshot.collection_overhead > self.sampling_config.overhead_threshold {
            self.metrics_manager.adjust_sampling_rate(
                crate::core::metrics::MetricCategory::System,
                0.8,
            )?;
        }

        histogram!("guardian.monitoring.collection_overhead", snapshot.collection_overhead);
        Ok(snapshot)
    }

    /// Performs comprehensive system health check
    #[instrument(skip(self))]
    #[activity(retry_policy = "exponential_backoff")]
    pub async fn check_system_health(&self) -> ActivityResult<SystemHealth> {
        let state = self.system_state.read();
        let current_state = state.get_current_state()?;

        // Check resource thresholds
        let health = if current_state.cpu_usage >= 80.0 || current_state.memory_usage >= 85.0 {
            SystemHealth::Critical
        } else if current_state.cpu_usage >= 70.0 || current_state.memory_usage >= 75.0 {
            SystemHealth::Degraded
        } else {
            SystemHealth::Healthy
        };

        // Record health metrics
        self.metrics_manager.record_system_metric(
            "system.health".into(),
            match health {
                SystemHealth::Healthy => 0.0,
                SystemHealth::Degraded => 1.0,
                SystemHealth::Critical => 2.0,
            },
            Some(crate::core::metrics::Priority::Critical),
        ).await?;

        counter!("guardian.monitoring.health_checks", 1);
        Ok(health)
    }

    /// Monitors and manages system resource usage
    #[instrument(skip(self))]
    #[activity(retry_policy = "exponential_backoff")]
    pub async fn monitor_resource_usage(&self) -> ActivityResult<ResourceUsage> {
        let start_time = Instant::now();
        let mut usage = ResourceUsage {
            cpu_utilization: 0.0,
            memory_consumption: 0.0,
            io_operations: 0,
            monitoring_overhead: 0.0,
            timestamp: time::OffsetDateTime::now_utc(),
        };

        // Monitor CPU utilization with sampling
        let state = self.system_state.read();
        usage.cpu_utilization = state.get_current_state()?.cpu_usage;
        self.metrics_manager.record_system_metric(
            "resource.cpu_utilization".into(),
            usage.cpu_utilization,
            Some(crate::core::metrics::Priority::High),
        ).await?;

        // Monitor memory consumption
        usage.memory_consumption = state.get_current_state()?.memory_usage;
        self.metrics_manager.record_system_metric(
            "resource.memory_consumption".into(),
            usage.memory_consumption,
            Some(crate::core::metrics::Priority::High),
        ).await?;

        // Calculate monitoring overhead
        usage.monitoring_overhead = start_time.elapsed().as_secs_f64() * 100.0;
        histogram!("guardian.monitoring.resource_overhead", usage.monitoring_overhead);

        Ok(usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::metrics::MetricsCollector;

    #[tokio::test]
    async fn test_collect_system_metrics() {
        let metrics_config = crate::utils::metrics::MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(100),
            flush_interval: Some(Duration::from_secs(1)),
            sampling_rates: None,
        };

        let collector = MetricsCollector::new(metrics_config).unwrap();
        let metrics_manager = CoreMetricsManager::new(
            collector,
            crate::core::metrics::MetricsConfig {
                sampling_rates: std::collections::HashMap::new(),
                priority_levels: std::collections::HashMap::new(),
                buffer_size: 1000,
            },
        ).unwrap();

        let system_state = Arc::new(parking_lot::RwLock::new(SystemState::default()));
        let activities = MonitoringActivities::new(
            metrics_manager,
            system_state,
            None,
            None,
        );

        let result = activities.collect_system_metrics().await;
        assert!(result.is_ok());
    }
}