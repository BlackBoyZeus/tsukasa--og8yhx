use std::time::Duration;
use temporal_sdk::{ActivityOptions, Worker};
use tracing::{debug, error, info, instrument, warn};
use async_trait::async_trait;
use metrics::{counter, histogram};

use crate::utils::error::{GuardianError, ErrorCategory};

// Re-export activity implementations
mod security_activities;
mod monitoring_activities;
mod maintenance_activities;

pub use security_activities::SecurityActivities;
pub use monitoring_activities::MonitoringActivities;
pub use maintenance_activities::MaintenanceActivities;

// Constants for activity configuration
const ACTIVITY_NAMESPACE: &str = "guardian.activities";
const ACTIVITY_QUEUE: &str = "guardian_activity_queue";
const ACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Configuration for activity registration and execution
#[derive(Debug, Clone)]
pub struct ActivityConfig {
    namespace: String,
    queue: String,
    timeout: Duration,
    retry_policy: RetryPolicy,
    circuit_breaker_threshold: u32,
}

impl Default for ActivityConfig {
    fn default() -> Self {
        Self {
            namespace: ACTIVITY_NAMESPACE.to_string(),
            queue: ACTIVITY_QUEUE.to_string(),
            timeout: ACTIVITY_TIMEOUT,
            retry_policy: RetryPolicy::default(),
            circuit_breaker_threshold: CIRCUIT_BREAKER_THRESHOLD,
        }
    }
}

/// Retry policy for activity execution
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    initial_interval: Duration,
    backoff: f64,
    max_interval: Duration,
    max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_interval: Duration::from_secs(1),
            backoff: 2.0,
            max_interval: Duration::from_secs(30),
            max_attempts: 3,
        }
    }
}

/// Registers all Guardian activities with the Temporal worker
#[instrument(skip(worker, config))]
pub async fn register_activities(
    worker: &Worker,
    config: ActivityConfig,
) -> Result<(), GuardianError> {
    info!("Registering Guardian activities with Temporal worker");

    // Initialize activity metrics
    counter!("guardian.activities.registration", 1);
    let start_time = std::time::Instant::now();

    // Configure activity options
    let options = configure_activity_options(&config);

    // Register security activities
    worker.register_activity(
        "analyze_threat_activity",
        options.clone(),
        SecurityActivities::analyze_threat_activity,
    ).map_err(|e| GuardianError::SystemError {
        context: "Failed to register security activities".into(),
        source: Some(Box::new(e)),
        severity: crate::utils::error::ErrorSeverity::Critical,
        timestamp: time::OffsetDateTime::now_utc(),
        correlation_id: uuid::Uuid::new_v4(),
        category: ErrorCategory::System,
        retry_count: 0,
    })?;

    // Register monitoring activities
    worker.register_activity(
        "collect_system_metrics",
        options.clone(),
        MonitoringActivities::collect_system_metrics,
    ).map_err(|e| GuardianError::SystemError {
        context: "Failed to register monitoring activities".into(),
        source: Some(Box::new(e)),
        severity: crate::utils::error::ErrorSeverity::Critical,
        timestamp: time::OffsetDateTime::now_utc(),
        correlation_id: uuid::Uuid::new_v4(),
        category: ErrorCategory::System,
        retry_count: 0,
    })?;

    // Register maintenance activities
    worker.register_activity(
        "perform_health_check",
        options.clone(),
        MaintenanceActivities::perform_health_check,
    ).map_err(|e| GuardianError::SystemError {
        context: "Failed to register maintenance activities".into(),
        source: Some(Box::new(e)),
        severity: crate::utils::error::ErrorSeverity::Critical,
        timestamp: time::OffsetDateTime::now_utc(),
        correlation_id: uuid::Uuid::new_v4(),
        category: ErrorCategory::System,
        retry_count: 0,
    })?;

    // Record registration metrics
    histogram!(
        "guardian.activities.registration_time",
        start_time.elapsed().as_secs_f64(),
    );

    info!("Successfully registered all Guardian activities");
    Ok(())
}

/// Configures activity execution options
fn configure_activity_options(config: &ActivityConfig) -> ActivityOptions {
    ActivityOptions {
        task_queue: config.queue.clone(),
        start_to_close_timeout: Some(config.timeout),
        retry_policy: Some(temporal_sdk::RetryPolicy {
            initial_interval: config.retry_policy.initial_interval,
            backoff_coefficient: config.retry_policy.backoff,
            maximum_interval: config.retry_policy.max_interval,
            maximum_attempts: config.retry_policy.max_attempts,
            non_retryable_error_types: vec![
                "ValidationError".to_string(),
                "SecurityError".to_string(),
            ],
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use temporal_sdk::Worker;

    #[tokio::test]
    async fn test_activity_registration() {
        let worker = Worker::new(
            "test_namespace".to_string(),
            "test_task_queue".to_string(),
            Default::default(),
        );

        let config = ActivityConfig::default();
        let result = register_activities(&worker, config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_activity_options() {
        let config = ActivityConfig::default();
        let options = configure_activity_options(&config);
        assert_eq!(options.task_queue, ACTIVITY_QUEUE);
        assert_eq!(options.start_to_close_timeout, Some(ACTIVITY_TIMEOUT));
    }
}