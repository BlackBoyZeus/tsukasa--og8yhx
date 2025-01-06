use metrics::{counter, gauge, histogram};
use metrics_exporter_statsd::{StatsdClient, StatsdExporter};
use parking_lot::{RwLock, RwLockReadGuard};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::time;

use crate::utils::error::GuardianError;
use crate::utils::metrics::{MetricsCollector, MetricPriority};

// Core metrics constants
const SYSTEM_METRICS_PREFIX: &str = "guardian.system";
const SECURITY_METRICS_PREFIX: &str = "guardian.security";
const ML_METRICS_PREFIX: &str = "guardian.ml";
const AGGREGATION_INTERVAL: Duration = Duration::from_secs(300);
const DEFAULT_BUFFER_SIZE: usize = 10000;
const MAX_RETRY_ATTEMPTS: u32 = 3;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Categories for different types of metrics with priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricCategory {
    System,
    Security,
    ML,
}

/// Priority levels for metric processing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

/// Configuration for metrics management
#[derive(Debug, Clone)]
struct MetricsConfig {
    sampling_rates: HashMap<MetricCategory, f64>,
    priority_levels: HashMap<MetricCategory, Priority>,
    buffer_size: usize,
}

/// Circuit breaker for metrics processing
#[derive(Debug)]
struct CircuitBreaker {
    failures: AtomicUsize,
    last_failure: RwLock<time::Instant>,
    is_open: RwLock<bool>,
}

/// Enhanced metrics management with priority-based processing and adaptive sampling
#[derive(Debug)]
pub struct CoreMetricsManager {
    collector: MetricsCollector,
    metrics_lock: RwLock<HashMap<String, f64>>,
    sampling_rates: RwLock<HashMap<MetricCategory, f64>>,
    priority_config: RwLock<HashMap<MetricCategory, Priority>>,
    buffer_size: AtomicUsize,
    circuit_breaker: CircuitBreaker,
}

impl CoreMetricsManager {
    /// Creates a new CoreMetricsManager instance with enhanced configuration
    pub fn new(collector: MetricsCollector, config: MetricsConfig) -> Result<Self, GuardianError> {
        let manager = Self {
            collector,
            metrics_lock: RwLock::new(HashMap::new()),
            sampling_rates: RwLock::new(config.sampling_rates),
            priority_config: RwLock::new(config.priority_levels),
            buffer_size: AtomicUsize::new(config.buffer_size),
            circuit_breaker: CircuitBreaker {
                failures: AtomicUsize::new(0),
                last_failure: RwLock::new(time::Instant::now()),
                is_open: RwLock::new(false),
            },
        };

        // Start background aggregation task
        let manager_clone = manager.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(AGGREGATION_INTERVAL);
            loop {
                interval.tick().await;
                if let Err(e) = manager_clone.aggregate_metrics().await {
                    counter!("guardian.metrics.aggregation.errors", 1);
                    eprintln!("Error aggregating metrics: {:?}", e);
                }
            }
        });

        // Start health check task
        let manager_clone = manager.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                manager_clone.check_health().await;
            }
        });

        Ok(manager)
    }

    /// Records a system-level metric with priority and sampling
    pub async fn record_system_metric(
        &self,
        name: String,
        value: f64,
        priority: Option<Priority>,
    ) -> Result<(), GuardianError> {
        self.record_metric(MetricCategory::System, name, value, priority).await
    }

    /// Records a security-related metric with priority and sampling
    pub async fn record_security_metric(
        &self,
        name: String,
        value: f64,
        priority: Option<Priority>,
    ) -> Result<(), GuardianError> {
        self.record_metric(MetricCategory::Security, name, value, priority).await
    }

    /// Records an ML-related metric with priority and sampling
    pub async fn record_ml_metric(
        &self,
        name: String,
        value: f64,
        priority: Option<Priority>,
    ) -> Result<(), GuardianError> {
        self.record_metric(MetricCategory::ML, name, value, priority).await
    }

    /// Sets the sampling rate for a specific metric category
    pub fn set_sampling_rate(&self, category: MetricCategory, rate: f64) -> Result<(), GuardianError> {
        if !(0.0..=1.0).contains(&rate) {
            return Err(GuardianError::SystemError {
                context: "Sampling rate must be between 0.0 and 1.0".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        self.sampling_rates.write().insert(category, rate);
        Ok(())
    }

    /// Configures priority level for a metric category
    pub fn configure_priority(
        &self,
        category: MetricCategory,
        priority: Priority,
    ) -> Result<(), GuardianError> {
        self.priority_config.write().insert(category, priority);
        Ok(())
    }

    // Private helper methods
    async fn record_metric(
        &self,
        category: MetricCategory,
        name: String,
        value: f64,
        priority: Option<Priority>,
    ) -> Result<(), GuardianError> {
        if self.circuit_breaker.is_open.read().clone() {
            return Err(GuardianError::SystemError {
                context: "Circuit breaker is open for metrics".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            });
        }

        let prefix = match category {
            MetricCategory::System => SYSTEM_METRICS_PREFIX,
            MetricCategory::Security => SECURITY_METRICS_PREFIX,
            MetricCategory::ML => ML_METRICS_PREFIX,
        };

        let metric_name = format!("{}.{}", prefix, name);
        let priority = priority.unwrap_or_else(|| {
            self.priority_config
                .read()
                .get(&category)
                .copied()
                .unwrap_or(Priority::Medium)
        });

        let sampling_rate = self.sampling_rates.read().get(&category).copied().unwrap_or(1.0);
        if rand::random::<f64>() > sampling_rate {
            return Ok(());
        }

        self.collector
            .record_metric(
                metric_name,
                value,
                crate::utils::metrics::MetricType::Gauge,
                match priority {
                    Priority::Critical => MetricPriority::Critical,
                    Priority::High => MetricPriority::High,
                    Priority::Medium => MetricPriority::Medium,
                    Priority::Low => MetricPriority::Low,
                },
                None,
            )
            .map_err(|e| GuardianError::SystemError {
                context: "Failed to record metric".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            })?;

        self.metrics_lock.write().insert(metric_name, value);
        Ok(())
    }

    async fn aggregate_metrics(&self) -> Result<(), GuardianError> {
        let metrics = self.collector.collect_metrics(None).await?;
        
        for metric in metrics {
            gauge!(
                &metric.name,
                metric.value,
                "category" => metric.tags.get("category").unwrap_or(&"unknown".to_string()).clone()
            );
        }

        counter!("guardian.metrics.aggregation.success", 1);
        Ok(())
    }

    async fn check_health(&self) {
        let failures = self.circuit_breaker.failures.load(Ordering::Relaxed);
        let last_failure = *self.circuit_breaker.last_failure.read();
        let now = time::Instant::now();

        if failures >= CIRCUIT_BREAKER_THRESHOLD {
            *self.circuit_breaker.is_open.write() = true;
            counter!("guardian.metrics.circuit_breaker.open", 1);
        } else if now.duration_since(last_failure) > Duration::from_secs(300) {
            self.circuit_breaker.failures.store(0, Ordering::Relaxed);
            *self.circuit_breaker.is_open.write() = false;
        }
    }
}

impl Clone for CoreMetricsManager {
    fn clone(&self) -> Self {
        Self {
            collector: self.collector.clone(),
            metrics_lock: RwLock::new(self.metrics_lock.read().clone()),
            sampling_rates: RwLock::new(self.sampling_rates.read().clone()),
            priority_config: RwLock::new(self.priority_config.read().clone()),
            buffer_size: AtomicUsize::new(self.buffer_size.load(Ordering::Relaxed)),
            circuit_breaker: CircuitBreaker {
                failures: AtomicUsize::new(self.circuit_breaker.failures.load(Ordering::Relaxed)),
                last_failure: RwLock::new(*self.circuit_breaker.last_failure.read()),
                is_open: RwLock::new(*self.circuit_breaker.is_open.read()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::metrics::MetricsConfig as CollectorConfig;

    #[tokio::test]
    async fn test_metric_recording() {
        let collector_config = CollectorConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(100),
            flush_interval: Some(Duration::from_secs(1)),
            sampling_rates: None,
        };

        let collector = MetricsCollector::new(collector_config).unwrap();
        let config = MetricsConfig {
            sampling_rates: HashMap::new(),
            priority_levels: HashMap::new(),
            buffer_size: DEFAULT_BUFFER_SIZE,
        };

        let manager = CoreMetricsManager::new(collector, config).unwrap();
        
        assert!(manager
            .record_system_metric("test.metric".into(), 1.0, Some(Priority::High))
            .await
            .is_ok());
    }
}