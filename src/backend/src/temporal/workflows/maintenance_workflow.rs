use std::time::Duration;
use async_trait::async_trait;
use temporal_sdk::{
    workflow,
    workflow::{Context, WorkflowResult},
    ActivityOptions, RetryPolicy,
};
use tracing::{info, warn, error, instrument};
use thiserror::Error;
use serde::{Serialize, Deserialize};

use crate::temporal::activities::maintenance_activities::{
    MaintenanceActivities,
    SystemHealthResult,
    OptimizationResult,
};
use crate::core::system_state::{SystemState, SystemHealth};
use crate::utils::error::GuardianError;

// Constants for workflow configuration
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(300);
const RESOURCE_OPTIMIZATION_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_RETRY_ATTEMPTS: u32 = 3;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Circuit breaker for maintenance workflow
#[derive(Debug)]
struct CircuitBreaker {
    failures: u32,
    last_failure: time::OffsetDateTime,
    is_open: bool,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failures: 0,
            last_failure: time::OffsetDateTime::now_utc(),
            is_open: false,
        }
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = time::OffsetDateTime::now_utc();
        if self.failures >= CIRCUIT_BREAKER_THRESHOLD {
            self.is_open = true;
        }
    }

    fn record_success(&mut self) {
        self.failures = 0;
        self.is_open = false;
    }
}

/// Workflow state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MaintenanceState {
    last_health_check: Option<SystemHealthResult>,
    last_optimization: Option<OptimizationResult>,
    circuit_breaker_state: bool,
    consecutive_failures: u32,
    last_failure_timestamp: time::OffsetDateTime,
}

/// Main maintenance workflow implementation
#[derive(Debug)]
#[workflow_version("2.0.0")]
pub struct MaintenanceWorkflow {
    activities: MaintenanceActivities,
    circuit_breaker: CircuitBreaker,
    state: MaintenanceState,
}

impl MaintenanceWorkflow {
    pub fn new(activities: MaintenanceActivities) -> Self {
        Self {
            activities,
            circuit_breaker: CircuitBreaker::new(),
            state: MaintenanceState {
                last_health_check: None,
                last_optimization: None,
                circuit_breaker_state: false,
                consecutive_failures: 0,
                last_failure_timestamp: time::OffsetDateTime::now_utc(),
            },
        }
    }

    fn health_check_retry_policy() -> RetryPolicy {
        RetryPolicy {
            initial_interval: Duration::from_secs(1),
            backoff: 2.0,
            max_interval: Duration::from_secs(10),
            max_attempts: MAX_RETRY_ATTEMPTS,
            non_retryable_error_types: vec!["ValidationError".to_string()],
        }
    }

    fn optimization_retry_policy() -> RetryPolicy {
        RetryPolicy {
            initial_interval: Duration::from_secs(5),
            backoff: 1.5,
            max_interval: Duration::from_secs(30),
            max_attempts: MAX_RETRY_ATTEMPTS,
            non_retryable_error_types: vec!["SystemError".to_string()],
        }
    }
}

#[async_trait]
impl MaintenanceWorkflow {
    /// Main workflow execution with enhanced error handling
    #[instrument(skip(self))]
    #[workflow::workflow]
    pub async fn execute_maintenance(&mut self) -> WorkflowResult<()> {
        info!("Starting maintenance workflow execution");
        
        let ctx = workflow::Context::current();
        
        loop {
            // Schedule health check with circuit breaker protection
            if !self.circuit_breaker.is_open {
                match self.schedule_health_check().await {
                    Ok(health_result) => {
                        self.state.last_health_check = Some(health_result);
                        self.circuit_breaker.record_success();
                    }
                    Err(e) => {
                        error!(?e, "Health check failed");
                        self.circuit_breaker.record_failure();
                    }
                }
            }

            // Schedule resource optimization if system is healthy
            if let Some(health) = &self.state.last_health_check {
                if health.status == SystemHealth::Healthy {
                    match self.schedule_resource_optimization().await {
                        Ok(opt_result) => {
                            self.state.last_optimization = Some(opt_result);
                            info!("Resource optimization completed successfully");
                        }
                        Err(e) => {
                            warn!(?e, "Resource optimization failed");
                            self.state.consecutive_failures += 1;
                        }
                    }
                }
            }

            // Persist workflow state
            ctx.persist_workflow_state(&self.state)?;

            // Wait for next maintenance cycle
            ctx.timer(HEALTH_CHECK_INTERVAL).await?;
        }
    }

    /// Schedules and executes health checks with retry logic
    #[instrument(skip(self))]
    async fn schedule_health_check(&self) -> Result<SystemHealthResult, GuardianError> {
        let ctx = workflow::Context::current();
        let activity_options = ActivityOptions {
            retry_policy: Some(Self::health_check_retry_policy()),
            ..Default::default()
        };

        ctx.with_activity_options(activity_options)
            .activity()
            .perform_health_check()
            .await
            .map_err(|e| GuardianError::SystemError {
                context: "Health check activity failed".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            })
    }

    /// Schedules and executes resource optimization with ML guidance
    #[instrument(skip(self))]
    async fn schedule_resource_optimization(&self) -> Result<OptimizationResult, GuardianError> {
        let ctx = workflow::Context::current();
        let activity_options = ActivityOptions {
            retry_policy: Some(Self::optimization_retry_policy()),
            ..Default::default()
        };

        ctx.with_activity_options(activity_options)
            .activity()
            .optimize_resources()
            .await
            .map_err(|e| GuardianError::SystemError {
                context: "Resource optimization activity failed".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::metrics::CoreMetricsManager;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_maintenance_workflow() {
        let system_state = Arc::new(SystemState::new(
            CoreMetricsManager::new(
                MetricsCollector::new(MetricsConfig {
                    statsd_host: "localhost".into(),
                    statsd_port: 8125,
                    buffer_size: Some(100),
                    flush_interval: Some(Duration::from_secs(1)),
                    sampling_rates: None,
                }).unwrap(),
                MetricsConfig {
                    sampling_rates: HashMap::new(),
                    priority_levels: HashMap::new(),
                    buffer_size: 1000,
                },
            ).unwrap(),
        ).unwrap());

        let activities = MaintenanceActivities::new(system_state);
        let workflow = MaintenanceWorkflow::new(activities);
        
        // Test workflow execution
        let result = workflow.execute_maintenance().await;
        assert!(result.is_ok());
    }
}