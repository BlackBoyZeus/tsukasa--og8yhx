use async_trait::async_trait;
use metrics::{counter, gauge, histogram};
use temporal_sdk::{
    WfContext, WfExecution, WfResult,
    workflow::{WorkflowOptions, WorkflowRetryPolicy},
};
use tracing::{debug, error, info, instrument, warn};

// Re-export workflow implementations
pub use self::security_workflow::{SecurityWorkflow, SecurityWorkflowImpl};
pub use self::monitoring_workflow::MonitoringWorkflow;
pub use self::maintenance_workflow::MaintenanceWorkflow;

// Core workflow module constants
const WORKFLOW_NAMESPACE: &str = "guardian.workflows";
const WORKFLOW_TASK_QUEUE: &str = "guardian.workflows.default";
const DEFAULT_WORKFLOW_TIMEOUT: Duration = Duration::from_secs(3600);
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Registers all Guardian system workflows with the Temporal server
#[tracing::instrument(level = "info", err)]
#[circuit_breaker(threshold = "CIRCUIT_BREAKER_THRESHOLD")]
pub async fn register_workflows(
    client: temporal_sdk::Client,
    config: WorkflowConfig,
) -> Result<(), GuardianError> {
    info!("Registering Guardian system workflows");

    // Configure default workflow options
    let default_options = WorkflowOptions {
        task_queue: WORKFLOW_TASK_QUEUE.to_string(),
        workflow_execution_timeout: Some(DEFAULT_WORKFLOW_TIMEOUT),
        retry_policy: Some(WorkflowRetryPolicy {
            initial_interval: Duration::from_secs(1),
            backoff_coefficient: 2.0,
            maximum_interval: Duration::from_secs(60),
            maximum_attempts: MAX_RETRY_ATTEMPTS,
            non_retryable_error_types: vec![
                "ValidationError".to_string(),
                "SecurityError".to_string(),
            ],
        }),
        ..Default::default()
    };

    // Register security workflow
    client
        .register_workflow(
            SecurityWorkflowImpl::new(config.security_config.clone()),
            "security_workflow",
            &default_options,
        )
        .await
        .map_err(|e| GuardianError::SystemError {
            context: "Failed to register security workflow".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::System,
            retry_count: 0,
        })?;

    // Register monitoring workflow
    client
        .register_workflow(
            MonitoringWorkflow::new(
                config.metrics_manager.clone(),
                config.system_state.clone(),
                config.retry_policy.clone(),
            ),
            "monitoring_workflow",
            &default_options,
        )
        .await
        .map_err(|e| GuardianError::SystemError {
            context: "Failed to register monitoring workflow".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::System,
            retry_count: 0,
        })?;

    // Register maintenance workflow
    client
        .register_workflow(
            MaintenanceWorkflow::new(config.maintenance_activities.clone()),
            "maintenance_workflow",
            &default_options,
        )
        .await
        .map_err(|e| GuardianError::SystemError {
            context: "Failed to register maintenance workflow".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::System,
            retry_count: 0,
        })?;

    info!("Successfully registered all Guardian workflows");
    counter!("guardian.workflows.registration.success", 1);

    Ok(())
}

/// Initializes the Temporal workflow execution environment
#[tracing::instrument(level = "info", err)]
pub async fn initialize_workflow_environment(
    config: WorkflowConfig,
) -> Result<temporal_sdk::Client, GuardianError> {
    info!("Initializing Temporal workflow environment");

    // Configure client with enhanced monitoring
    let client = temporal_sdk::Client::new(
        temporal_sdk::ConnectionOptions::default()
            .set_identity("guardian_system")
            .set_namespace(WORKFLOW_NAMESPACE)
            .set_target_url(&config.temporal_url)
            .set_retry_config(temporal_sdk::RetryConfig::default()
                .set_initial_interval(Duration::from_secs(1))
                .set_max_attempts(MAX_RETRY_ATTEMPTS)),
    )
    .await
    .map_err(|e| GuardianError::SystemError {
        context: "Failed to initialize Temporal client".into(),
        source: Some(Box::new(e)),
        severity: crate::utils::error::ErrorSeverity::Critical,
        timestamp: time::OffsetDateTime::now_utc(),
        correlation_id: uuid::Uuid::new_v4(),
        category: crate::utils::error::ErrorCategory::System,
        retry_count: 0,
    })?;

    // Initialize workflow metrics collection
    gauge!("guardian.workflows.initialization", 1.0);

    // Register workflows with the initialized client
    register_workflows(client.clone(), config).await?;

    Ok(client)
}

// Internal modules
mod security_workflow;
mod monitoring_workflow;
mod maintenance_workflow;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_workflow_registration() {
        let config = WorkflowConfig {
            temporal_url: "localhost:7233".to_string(),
            security_config: Default::default(),
            metrics_manager: Arc::new(create_test_metrics_manager()),
            system_state: Arc::new(create_test_system_state()),
            retry_policy: Default::default(),
            maintenance_activities: create_test_maintenance_activities(),
        };

        let result = initialize_workflow_environment(config).await;
        assert!(result.is_ok());
    }

    // Helper functions for creating test dependencies
    fn create_test_metrics_manager() -> CoreMetricsManager {
        // Implementation omitted for brevity
        unimplemented!()
    }

    fn create_test_system_state() -> SystemState {
        // Implementation omitted for brevity
        unimplemented!()
    }

    fn create_test_maintenance_activities() -> MaintenanceActivities {
        // Implementation omitted for brevity
        unimplemented!()
    }
}