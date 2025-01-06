use std::{sync::Arc, time::Duration};
use temporal_sdk::{Client, Runtime, Worker, WorkerOptions};
use tracing::{debug, error, info, instrument, warn};
use metrics::{counter, gauge, histogram};

use crate::utils::error::{GuardianError, ErrorCategory, ErrorSeverity};

// Re-export activity and workflow implementations
pub mod activities;
pub mod workflows;

pub use activities::{SecurityActivities, MonitoringActivities, MaintenanceActivities};
pub use workflows::{SecurityWorkflow, MonitoringWorkflow, MaintenanceWorkflow};

// Core constants for Temporal configuration
const TEMPORAL_NAMESPACE: &str = "guardian";
const DEFAULT_TASK_QUEUE: &str = "guardian.default";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3600);
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const MAX_CONCURRENT_WORKFLOWS: usize = 1000;

/// Configuration for Temporal runtime initialization
#[derive(Debug, Clone)]
pub struct TemporalConfig {
    pub namespace: String,
    pub task_queue: String,
    pub worker_options: WorkerOptions,
    pub timeout: Duration,
    pub metrics_enabled: bool,
}

impl Default for TemporalConfig {
    fn default() -> Self {
        Self {
            namespace: TEMPORAL_NAMESPACE.to_string(),
            task_queue: DEFAULT_TASK_QUEUE.to_string(),
            worker_options: WorkerOptions {
                max_concurrent_workflow_task_pollers: MAX_CONCURRENT_WORKFLOWS,
                max_concurrent_activities: MAX_CONCURRENT_WORKFLOWS,
                ..Default::default()
            },
            timeout: DEFAULT_TIMEOUT,
            metrics_enabled: true,
        }
    }
}

/// Core Temporal runtime management
#[derive(Debug)]
pub struct TemporalRuntime {
    client: Arc<Client>,
    worker: Arc<Worker>,
    config: TemporalConfig,
    circuit_breaker_failures: std::sync::atomic::AtomicU32,
}

impl TemporalRuntime {
    /// Initializes the Temporal runtime with enhanced error handling and telemetry
    #[instrument(skip(config, metrics), fields(namespace = %config.namespace))]
    pub async fn initialize(
        config: TemporalConfig,
        metrics: Arc<crate::core::metrics::CoreMetricsManager>,
    ) -> Result<Self, GuardianError> {
        info!("Initializing Temporal runtime");

        // Initialize Temporal client with retry policy
        let client = Client::new(
            temporal_sdk::ConnectionOptions::default()
                .set_identity("guardian_system")
                .set_namespace(&config.namespace)
                .set_target_url("localhost:7233"),
        )
        .await
        .map_err(|e| GuardianError::SystemError {
            context: "Failed to initialize Temporal client".into(),
            source: Some(Box::new(e)),
            severity: ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::System,
            retry_count: 0,
        })?;

        // Create worker with configured options
        let worker = Worker::new(
            client.clone(),
            config.task_queue.clone(),
            config.worker_options.clone(),
        );

        // Register activities with versioning
        activities::register_activities(&worker, activities::ActivityConfig::default())
            .await
            .map_err(|e| GuardianError::SystemError {
                context: "Failed to register activities".into(),
                source: Some(Box::new(e)),
                severity: ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::System,
                retry_count: 0,
            })?;

        // Register workflows with correlation
        workflows::register_workflows(
            client.clone(),
            workflows::WorkflowConfig {
                temporal_url: "localhost:7233".to_string(),
                security_config: Default::default(),
                metrics_manager: metrics,
                system_state: Arc::new(parking_lot::RwLock::new(
                    crate::core::system_state::SystemState::default(),
                )),
                retry_policy: Default::default(),
                maintenance_activities: MaintenanceActivities::default(),
            },
        )
        .await?;

        let runtime = Self {
            client: Arc::new(client),
            worker: Arc::new(worker),
            config,
            circuit_breaker_failures: std::sync::atomic::AtomicU32::new(0),
        };

        // Start worker
        runtime.worker.start().await.map_err(|e| GuardianError::SystemError {
            context: "Failed to start Temporal worker".into(),
            source: Some(Box::new(e)),
            severity: ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::System,
            retry_count: 0,
        })?;

        info!("Temporal runtime initialized successfully");
        Ok(runtime)
    }

    /// Gracefully shuts down the Temporal runtime with resource cleanup
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<(), GuardianError> {
        info!("Shutting down Temporal runtime");

        // Stop accepting new workflows
        self.worker.stop().await;

        // Wait for active workflows to complete
        let timeout = Duration::from_secs(30);
        tokio::time::timeout(timeout, self.worker.wait_until_stopped())
            .await
            .map_err(|_| GuardianError::SystemError {
                context: "Timeout waiting for worker shutdown".into(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::System,
                retry_count: 0,
            })?;

        info!("Temporal runtime shutdown completed");
        Ok(())
    }

    /// Performs health check of the Temporal runtime
    pub async fn health_check(&self) -> Result<bool, GuardianError> {
        let failures = self.circuit_breaker_failures.load(std::sync::atomic::Ordering::Relaxed);
        if failures >= CIRCUIT_BREAKER_THRESHOLD {
            return Ok(false);
        }

        // Check client connectivity
        if let Err(e) = self.client.get_system_info().await {
            error!(?e, "Temporal client health check failed");
            self.circuit_breaker_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(false);
        }

        Ok(true)
    }

    /// Retrieves runtime metrics for monitoring
    pub fn get_metrics(&self) -> Result<Vec<(String, f64)>, GuardianError> {
        let mut metrics = Vec::new();

        // Collect worker metrics
        metrics.push((
            "guardian.temporal.workflows.active".into(),
            self.worker.get_running_workflows() as f64,
        ));
        metrics.push((
            "guardian.temporal.activities.active".into(),
            self.worker.get_running_activities() as f64,
        ));

        // Collect circuit breaker metrics
        metrics.push((
            "guardian.temporal.circuit_breaker.failures".into(),
            self.circuit_breaker_failures
                .load(std::sync::atomic::Ordering::Relaxed) as f64,
        ));

        Ok(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::metrics::MetricsConfig;

    #[tokio::test]
    async fn test_temporal_runtime() {
        let metrics_config = MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(100),
            flush_interval: Some(Duration::from_secs(1)),
            sampling_rates: None,
        };

        let collector = crate::utils::metrics::MetricsCollector::new(metrics_config).unwrap();
        let metrics_manager = Arc::new(crate::core::metrics::CoreMetricsManager::new(
            collector,
            crate::core::metrics::MetricsConfig {
                sampling_rates: std::collections::HashMap::new(),
                priority_levels: std::collections::HashMap::new(),
                buffer_size: 1000,
            },
        ).unwrap());

        let config = TemporalConfig::default();
        let runtime = TemporalRuntime::initialize(config, metrics_manager).await;
        assert!(runtime.is_ok());

        let runtime = runtime.unwrap();
        assert!(runtime.health_check().await.unwrap());
        assert!(runtime.shutdown().await.is_ok());
    }
}