use async_trait::async_trait;
use metrics::{counter, gauge, histogram};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use temporal_sdk::{
    ActivityOptions, RetryPolicy, WfContext, WorkflowContext, WorkflowResult,
    workflow_stub, workflow_trait,
};
use tokio::time;
use tracing::{debug, error, info, instrument, warn};

use crate::core::metrics::CoreMetricsManager;
use crate::core::system_state::{SystemHealth, SystemState};
use crate::temporal::activities::monitoring_activities::{
    MetricsSnapshot, MonitoringActivities, ResourceUsage,
};
use crate::utils::error::{GuardianError, ErrorSeverity, ErrorCategory};

// Core monitoring workflow constants
const MONITORING_CYCLE_INTERVAL: Duration = Duration::from_secs(60);
const MAX_WORKFLOW_RETRIES: u32 = 3;
const WORKFLOW_TIMEOUT: Duration = Duration::from_secs(300);
const ACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESOURCE_OVERHEAD: f64 = 0.05; // 5% maximum overhead
const PERFORMANCE_IMPACT_THRESHOLD: Duration = Duration::from_millis(100);

/// Result of a monitoring cycle execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringResult {
    pub metrics: MetricsSnapshot,
    pub health: SystemHealth,
    pub resource_usage: ResourceUsage,
    pub performance_impact: f64,
    pub timestamp: time::OffsetDateTime,
}

/// Performance tracking for monitoring activities
#[derive(Debug)]
struct PerformanceTracker {
    cycle_start: time::Instant,
    metrics_duration: Duration,
    health_check_duration: Duration,
    resource_monitor_duration: Duration,
}

/// Core monitoring workflow implementation
#[derive(Debug)]
#[workflow_trait::workflow]
#[async_trait::async_trait]
pub struct MonitoringWorkflow {
    metrics_manager: CoreMetricsManager,
    system_state: Arc<parking_lot::RwLock<SystemState>>,
    retry_policy: RetryPolicy,
    performance_tracker: PerformanceTracker,
}

impl MonitoringWorkflow {
    /// Creates a new MonitoringWorkflow instance with configured retry policies
    pub fn new(
        metrics_manager: CoreMetricsManager,
        system_state: Arc<parking_lot::RwLock<SystemState>>,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            metrics_manager,
            system_state,
            retry_policy,
            performance_tracker: PerformanceTracker {
                cycle_start: time::Instant::now(),
                metrics_duration: Duration::default(),
                health_check_duration: Duration::default(),
                resource_monitor_duration: Duration::default(),
            },
        }
    }

    /// Executes a complete monitoring cycle with performance tracking
    #[workflow]
    #[instrument(skip(self, ctx))]
    pub async fn execute_monitoring_cycle(
        &self,
        ctx: WorkflowContext,
    ) -> WorkflowResult<MonitoringResult> {
        let cycle_start = time::Instant::now();
        info!("Starting monitoring cycle");

        // Configure activity options with timeouts and retries
        let activity_options = ActivityOptions::new()
            .with_retry_policy(self.retry_policy.clone())
            .with_schedule_to_close_timeout(ACTIVITY_TIMEOUT)
            .with_schedule_to_start_timeout(Duration::from_secs(10));

        let activities = ctx.activity_stub(activity_options);
        let mut result = MonitoringResult {
            metrics: MetricsSnapshot {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                system_load: 0.0,
                collection_overhead: 0.0,
                timestamp: time::OffsetDateTime::now_utc(),
            },
            health: SystemHealth::Healthy,
            resource_usage: ResourceUsage {
                cpu_utilization: 0.0,
                memory_consumption: 0.0,
                io_operations: 0,
                monitoring_overhead: 0.0,
                timestamp: time::OffsetDateTime::now_utc(),
            },
            performance_impact: 0.0,
            timestamp: time::OffsetDateTime::now_utc(),
        };

        // Collect system metrics with performance tracking
        let metrics_start = time::Instant::now();
        match activities.collect_system_metrics().await {
            Ok(metrics) => {
                result.metrics = metrics;
                self.performance_tracker.metrics_duration = metrics_start.elapsed();
                histogram!("guardian.monitoring.metrics_collection_duration", 
                    self.performance_tracker.metrics_duration.as_secs_f64());
            }
            Err(e) => {
                self.handle_monitoring_failure(&ctx, e).await?;
            }
        }

        // Check system health with timeout protection
        let health_start = time::Instant::now();
        match activities.check_system_health().await {
            Ok(health) => {
                result.health = health;
                self.performance_tracker.health_check_duration = health_start.elapsed();
                histogram!("guardian.monitoring.health_check_duration",
                    self.performance_tracker.health_check_duration.as_secs_f64());
            }
            Err(e) => {
                self.handle_monitoring_failure(&ctx, e).await?;
            }
        }

        // Monitor resource usage with impact assessment
        let resource_start = time::Instant::now();
        match activities.monitor_resource_usage().await {
            Ok(usage) => {
                result.resource_usage = usage;
                self.performance_tracker.resource_monitor_duration = resource_start.elapsed();
                histogram!("guardian.monitoring.resource_monitor_duration",
                    self.performance_tracker.resource_monitor_duration.as_secs_f64());
            }
            Err(e) => {
                self.handle_monitoring_failure(&ctx, e).await?;
            }
        }

        // Calculate total performance impact
        let cycle_duration = cycle_start.elapsed();
        result.performance_impact = cycle_duration.as_secs_f64() / MONITORING_CYCLE_INTERVAL.as_secs_f64();
        
        // Validate monitoring overhead compliance
        if result.performance_impact > MAX_RESOURCE_OVERHEAD {
            warn!(
                impact = result.performance_impact,
                threshold = MAX_RESOURCE_OVERHEAD,
                "Monitoring overhead exceeded threshold"
            );
            counter!("guardian.monitoring.overhead_exceeded", 1);
        }

        // Update system state with comprehensive metrics
        if let Ok(mut state) = self.system_state.write() {
            state.update_state(SystemState {
                health: result.health.clone(),
                cpu_usage: result.metrics.cpu_usage,
                memory_usage: result.metrics.memory_usage,
                active_threats: 0, // Updated by security workflow
                last_update: time::OffsetDateTime::now_utc(),
                state_history: Default::default(),
                circuit_breaker: Default::default(),
                validation_rules: Vec::new(),
            }).await?;
        }

        result.timestamp = time::OffsetDateTime::now_utc();
        info!(
            duration = ?cycle_duration,
            impact = result.performance_impact,
            "Monitoring cycle completed successfully"
        );

        Ok(result)
    }

    /// Handles monitoring failures with context-aware retry logic
    #[workflow]
    #[instrument(skip(self, ctx, error))]
    async fn handle_monitoring_failure(
        &self,
        ctx: &WorkflowContext,
        error: GuardianError,
    ) -> WorkflowResult<()> {
        error!(
            ?error,
            retry_count = error.retry_count(),
            "Monitoring activity failed"
        );

        counter!("guardian.monitoring.failures", 1);

        // Record failure metrics with context
        self.metrics_manager.record_system_metric(
            "monitoring.failures".into(),
            1.0,
            Some(crate::core::metrics::Priority::High),
        ).await.map_err(|e| GuardianError::SystemError {
            context: "Failed to record failure metrics".into(),
            source: Some(Box::new(e)),
            severity: ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::System,
            retry_count: 0,
        })?;

        // Check if retry is possible
        if let Some(retryable_error) = error.increment_retry() {
            let backoff = Duration::from_secs(2u64.pow(retryable_error.retry_count()));
            ctx.timer(backoff).await;
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::metrics::MetricsConfig;

    #[tokio::test]
    async fn test_monitoring_cycle() {
        let metrics_config = MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(100),
            flush_interval: Some(Duration::from_secs(1)),
            sampling_rates: None,
        };

        let collector = crate::utils::metrics::MetricsCollector::new(metrics_config).unwrap();
        let metrics_manager = CoreMetricsManager::new(
            collector,
            crate::core::metrics::MetricsConfig {
                sampling_rates: std::collections::HashMap::new(),
                priority_levels: std::collections::HashMap::new(),
                buffer_size: 1000,
            },
        ).unwrap();

        let system_state = Arc::new(parking_lot::RwLock::new(SystemState::default()));
        let retry_policy = RetryPolicy::default()
            .with_initial_interval(Duration::from_secs(1))
            .with_maximum_attempts(MAX_WORKFLOW_RETRIES);

        let workflow = MonitoringWorkflow::new(
            metrics_manager,
            system_state,
            retry_policy,
        );

        // Test execution would require a full Temporal environment
        // This test setup demonstrates the configuration
        assert!(workflow.metrics_manager.record_system_metric(
            "test.metric".into(),
            1.0,
            Some(crate::core::metrics::Priority::High),
        ).await.is_ok());
    }
}