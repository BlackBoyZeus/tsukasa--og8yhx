use std::{sync::Arc, time::Duration};
use temporal_sdk::{
    WfContext, WfExecution, WfResult,
    workflow::{WorkflowOptions, WorkflowRetryPolicy},
};
use async_trait::async_trait;
use tracing::{debug, error, info, instrument, warn};
use serde::{Serialize, Deserialize};
use circuit_breaker::CircuitBreaker;

use crate::temporal::activities::security_activities::SecurityActivities;
use crate::security::threat_detection::ThreatLevel;
use crate::utils::error::GuardianError;

// Workflow version and configuration constants
const WORKFLOW_VERSION: &str = "1.0.0";
const DEFAULT_WORKFLOW_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_WORKFLOW_RETRIES: i32 = 3;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const CRITICAL_THREAT_TIMEOUT: Duration = Duration::from_millis(500);
const HIGH_THREAT_TIMEOUT: Duration = Duration::from_secs(2);

/// Configuration for security workflow execution
#[derive(Debug, Clone)]
pub struct SecurityWorkflowConfig {
    workflow_timeout: Duration,
    max_retries: i32,
    circuit_breaker_threshold: u32,
    critical_threat_timeout: Duration,
    high_threat_timeout: Duration,
    enable_metrics: bool,
}

impl Default for SecurityWorkflowConfig {
    fn default() -> Self {
        Self {
            workflow_timeout: DEFAULT_WORKFLOW_TIMEOUT,
            max_retries: MAX_WORKFLOW_RETRIES,
            circuit_breaker_threshold: CIRCUIT_BREAKER_THRESHOLD,
            critical_threat_timeout: CRITICAL_THREAT_TIMEOUT,
            high_threat_timeout: HIGH_THREAT_TIMEOUT,
            enable_metrics: true,
        }
    }
}

/// Metrics for workflow monitoring
#[derive(Debug, Clone)]
struct WorkflowMetrics {
    execution_time: Duration,
    threat_detection_time: Duration,
    response_time: Duration,
    retry_count: u32,
}

/// Core security workflow trait
#[async_trait]
pub trait SecurityWorkflow {
    async fn execute_security_workflow(
        &self,
        ctx: WfContext,
        system_data: SystemData,
    ) -> WfResult<WorkflowStatus>;
}

/// Implementation of security workflow with enhanced reliability
#[derive(Debug)]
#[workflow_impl]
#[async_trait::async_trait]
pub struct SecurityWorkflowImpl {
    workflow_config: SecurityWorkflowConfig,
    circuit_breaker: CircuitBreaker,
    metrics: WorkflowMetrics,
}

impl SecurityWorkflowImpl {
    /// Creates a new SecurityWorkflowImpl instance
    pub fn new(config: SecurityWorkflowConfig) -> Self {
        Self {
            workflow_config: config,
            circuit_breaker: CircuitBreaker::new(config.circuit_breaker_threshold),
            metrics: WorkflowMetrics {
                execution_time: Duration::default(),
                threat_detection_time: Duration::default(),
                response_time: Duration::default(),
                retry_count: 0,
            },
        }
    }

    /// Creates instance with custom configuration
    pub fn with_config(config: SecurityWorkflowConfig) -> Self {
        Self::new(config)
    }

    /// Main security workflow execution function
    #[tracing::instrument(skip(self, ctx))]
    #[workflow]
    pub async fn execute_security_workflow(
        &self,
        ctx: WfContext,
        system_data: SystemData,
    ) -> WfResult<WorkflowStatus> {
        info!(
            version = WORKFLOW_VERSION,
            "Starting security workflow execution"
        );

        let start_time = ctx.current_time();

        // Check circuit breaker
        if self.circuit_breaker.is_open() {
            error!("Circuit breaker is open, workflow execution blocked");
            return Err(GuardianError::WorkflowError {
                context: "Circuit breaker is open".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Security,
                retry_count: 0,
            });
        }

        // Configure activity options based on threat level
        let activity_options = match system_data.threat_level {
            ThreatLevel::Critical => ActivityOptions {
                start_to_close_timeout: Some(self.workflow_config.critical_threat_timeout),
                retry_policy: Some(RetryPolicy {
                    maximum_attempts: self.workflow_config.max_retries,
                    ..Default::default()
                }),
                ..Default::default()
            },
            ThreatLevel::High => ActivityOptions {
                start_to_close_timeout: Some(self.workflow_config.high_threat_timeout),
                retry_policy: Some(RetryPolicy {
                    maximum_attempts: self.workflow_config.max_retries,
                    ..Default::default()
                }),
                ..Default::default()
            },
            _ => ActivityOptions::default(),
        };

        // Execute threat detection activity
        let detection_start = ctx.current_time();
        let threat_analysis = ctx
            .activity(SecurityActivities::detect_threats)
            .activity_options(activity_options.clone())
            .arg(system_data)
            .await?;

        self.metrics.threat_detection_time = ctx.current_time() - detection_start;

        // Execute response if threats detected
        if threat_analysis.severity >= ThreatLevel::High {
            let response_start = ctx.current_time();
            let response_status = ctx
                .activity(SecurityActivities::execute_response)
                .activity_options(activity_options.clone())
                .arg(threat_analysis.clone())
                .await?;

            self.metrics.response_time = ctx.current_time() - response_start;

            // Record audit event
            ctx.activity(SecurityActivities::record_audit)
                .activity_options(activity_options)
                .arg(AuditEvent::new(
                    "security.response.executed",
                    SecurityLevel::High,
                    "security_workflow",
                    Some(response_status.correlation_id.to_string()),
                ))
                .await?;
        }

        // Update workflow metrics
        self.metrics.execution_time = ctx.current_time() - start_time;

        // Update circuit breaker state
        if self.workflow_config.enable_metrics {
            self.record_workflow_metrics(&ctx).await?;
        }

        Ok(WorkflowStatus {
            success: true,
            execution_time: self.metrics.execution_time,
            threat_detected: threat_analysis.severity >= ThreatLevel::High,
            correlation_id: uuid::Uuid::new_v4(),
        })
    }

    /// Records workflow execution metrics
    async fn record_workflow_metrics(&self, ctx: &WfContext) -> WfResult<()> {
        ctx.record_metric(
            "guardian.workflow.execution_time",
            self.metrics.execution_time.as_secs_f64(),
        );
        ctx.record_metric(
            "guardian.workflow.threat_detection_time",
            self.metrics.threat_detection_time.as_secs_f64(),
        );
        ctx.record_metric(
            "guardian.workflow.response_time",
            self.metrics.response_time.as_secs_f64(),
        );
        ctx.record_metric(
            "guardian.workflow.retry_count",
            self.metrics.retry_count as f64,
        );
        Ok(())
    }
}

/// Validates workflow configuration
#[tracing::instrument]
fn validate_workflow_config(config: &SecurityWorkflowConfig) -> Result<(), GuardianError> {
    if config.workflow_timeout < Duration::from_secs(1) {
        return Err(GuardianError::ValidationError {
            context: "Workflow timeout must be at least 1 second".into(),
            source: None,
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Validation,
            retry_count: 0,
        });
    }

    if config.max_retries < 0 {
        return Err(GuardianError::ValidationError {
            context: "Max retries cannot be negative".into(),
            source: None,
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Validation,
            retry_count: 0,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_workflow_execution() {
        let config = SecurityWorkflowConfig::default();
        let workflow = SecurityWorkflowImpl::new(config);

        let ctx = WfContext::new();
        let system_data = SystemData {
            threat_level: ThreatLevel::High,
            // ... other fields
        };

        let result = workflow.execute_security_workflow(ctx, system_data).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_validation() {
        let invalid_config = SecurityWorkflowConfig {
            workflow_timeout: Duration::from_millis(100),
            max_retries: -1,
            ..Default::default()
        };

        assert!(validate_workflow_config(&invalid_config).is_err());
    }
}