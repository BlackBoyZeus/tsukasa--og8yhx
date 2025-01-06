use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use temporal_sdk::{Client as TemporalClient, ClientOptions};
use tokio::{sync::broadcast, time};
use tracing::{debug, error, info, instrument, warn};

use crate::utils::error::GuardianError;
use crate::core::metrics::CoreMetricsManager;
use crate::core::event_bus::{Event, EventBus, EventPriority};
use crate::core::system_state::{SystemHealth, SystemState};

// Core system constants
const SYSTEM_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_TEMPORAL_NAMESPACE: &str = "guardian";
const DEFAULT_METRICS_PREFIX: &str = "guardian.core";
const DEFAULT_EVENT_BUS_CAPACITY: usize = 10_000;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for the Guardian system
#[derive(Debug, Clone, Deserialize)]
pub struct GuardianConfig {
    pub temporal_namespace: String,
    pub metrics_prefix: String,
    pub log_level: String,
    pub event_bus_capacity: usize,
    pub monitor_interval: Duration,
    pub circuit_breaker_threshold: u32,
}

impl GuardianConfig {
    /// Creates configuration from environment variables
    pub fn from_env() -> Result<Self, GuardianError> {
        Ok(Self {
            temporal_namespace: std::env::var("GUARDIAN_TEMPORAL_NAMESPACE")
                .unwrap_or_else(|_| DEFAULT_TEMPORAL_NAMESPACE.to_string()),
            metrics_prefix: std::env::var("GUARDIAN_METRICS_PREFIX")
                .unwrap_or_else(|_| DEFAULT_METRICS_PREFIX.to_string()),
            log_level: std::env::var("GUARDIAN_LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            event_bus_capacity: std::env::var("GUARDIAN_EVENT_BUS_CAPACITY")
                .map(|v| v.parse().unwrap_or(DEFAULT_EVENT_BUS_CAPACITY))
                .unwrap_or(DEFAULT_EVENT_BUS_CAPACITY),
            monitor_interval: Duration::from_secs(
                std::env::var("GUARDIAN_MONITOR_INTERVAL")
                    .map(|v| v.parse().unwrap_or(60))
                    .unwrap_or(60),
            ),
            circuit_breaker_threshold: std::env::var("GUARDIAN_CIRCUIT_BREAKER_THRESHOLD")
                .map(|v| v.parse().unwrap_or(CIRCUIT_BREAKER_THRESHOLD))
                .unwrap_or(CIRCUIT_BREAKER_THRESHOLD),
        })
    }

    /// Validates configuration parameters
    pub fn validate(&self) -> Result<(), GuardianError> {
        if self.event_bus_capacity == 0 {
            return Err(GuardianError::ValidationError {
                context: "Event bus capacity must be greater than 0".into(),
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
}

/// Circuit breaker for system operations
#[derive(Debug)]
struct CircuitBreaker {
    failures: AtomicBool,
    threshold: u32,
}

/// Core Guardian system coordinator
#[derive(Debug)]
pub struct Guardian {
    event_bus: EventBus,
    metrics: CoreMetricsManager,
    system_state: Arc<RwLock<SystemState>>,
    temporal_client: TemporalClient,
    shutdown_signal: broadcast::Sender<()>,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl Guardian {
    /// Creates a new Guardian instance with validated configuration
    #[instrument(skip(config))]
    pub async fn new(config: GuardianConfig) -> Result<Self, GuardianError> {
        config.validate()?;

        // Initialize event bus
        let event_bus = EventBus::new(CoreMetricsManager::new(
            crate::utils::metrics::MetricsCollector::new(
                crate::utils::metrics::MetricsConfig {
                    statsd_host: "localhost".into(),
                    statsd_port: 8125,
                    buffer_size: Some(config.event_bus_capacity),
                    flush_interval: Some(Duration::from_secs(10)),
                    sampling_rates: None,
                },
            )?,
            crate::core::metrics::MetricsConfig {
                sampling_rates: std::collections::HashMap::new(),
                priority_levels: std::collections::HashMap::new(),
                buffer_size: config.event_bus_capacity,
            },
        )?)?;

        // Initialize Temporal client
        let temporal_client = TemporalClient::connect(ClientOptions::default().namespace(&config.temporal_namespace))
            .await
            .map_err(|e| GuardianError::SystemError {
                context: "Failed to connect to Temporal".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            })?;

        let (shutdown_tx, _) = broadcast::channel(1);

        let guardian = Self {
            event_bus,
            metrics: CoreMetricsManager::new(
                crate::utils::metrics::MetricsCollector::new(
                    crate::utils::metrics::MetricsConfig {
                        statsd_host: "localhost".into(),
                        statsd_port: 8125,
                        buffer_size: Some(config.event_bus_capacity),
                        flush_interval: Some(Duration::from_secs(10)),
                        sampling_rates: None,
                    },
                )?,
                crate::core::metrics::MetricsConfig {
                    sampling_rates: std::collections::HashMap::new(),
                    priority_levels: std::collections::HashMap::new(),
                    buffer_size: config.event_bus_capacity,
                },
            )?,
            system_state: SystemState::new(
                crate::utils::metrics::MetricsCollector::new(
                    crate::utils::metrics::MetricsConfig {
                        statsd_host: "localhost".into(),
                        statsd_port: 8125,
                        buffer_size: Some(config.event_bus_capacity),
                        flush_interval: Some(Duration::from_secs(10)),
                        sampling_rates: None,
                    },
                )?,
                event_bus.clone(),
                crate::core::system_state::StateConfig {
                    history_capacity: 1000,
                    validation_timeout: Duration::from_millis(50),
                    health_check_interval: config.monitor_interval,
                },
            )?,
            temporal_client,
            shutdown_signal: shutdown_tx,
            circuit_breaker: Arc::new(CircuitBreaker {
                failures: AtomicBool::new(false),
                threshold: config.circuit_breaker_threshold,
            }),
        };

        // Start system monitoring
        let guardian_clone = Arc::new(guardian.clone());
        tokio::spawn(monitor_system(guardian_clone));

        Ok(guardian)
    }

    /// Starts the Guardian system with enhanced error handling
    #[instrument]
    pub async fn start(&self) -> Result<(), GuardianError> {
        info!("Starting Guardian system");

        // Verify system prerequisites
        let state = self.system_state.read();
        if state.get_current_state()?.health == SystemHealth::Critical {
            return Err(GuardianError::SystemError {
                context: "Cannot start system in critical state".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            });
        }

        // Start core workflows
        self.start_workflows().await?;

        info!("Guardian system started successfully");
        Ok(())
    }

    /// Gracefully shuts down the Guardian system
    #[instrument]
    pub async fn shutdown(&self) -> Result<(), GuardianError> {
        info!("Initiating Guardian system shutdown");

        // Broadcast shutdown signal
        let _ = self.shutdown_signal.send(());

        // Wait for components to shutdown
        time::sleep(SHUTDOWN_TIMEOUT).await;

        // Cleanup resources
        self.event_bus.shutdown().await?;
        self.metrics
            .record_system_metric("system.shutdown".into(), 1.0, None)
            .await?;

        info!("Guardian system shutdown complete");
        Ok(())
    }

    // Private helper methods
    async fn start_workflows(&self) -> Result<(), GuardianError> {
        // Start core workflow
        self.temporal_client
            .start_workflow("guardian-core", (), None)
            .await
            .map_err(|e| GuardianError::SystemError {
                context: "Failed to start core workflow".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            })?;

        Ok(())
    }
}

impl Clone for Guardian {
    fn clone(&self) -> Self {
        Self {
            event_bus: self.event_bus.clone(),
            metrics: self.metrics.clone(),
            system_state: Arc::clone(&self.system_state),
            temporal_client: self.temporal_client.clone(),
            shutdown_signal: self.shutdown_signal.clone(),
            circuit_breaker: Arc::clone(&self.circuit_breaker),
        }
    }
}

/// Background task monitoring system health
#[instrument(skip(guardian))]
async fn monitor_system(guardian: Arc<Guardian>) -> Result<(), GuardianError> {
    let mut interval = time::interval(SYSTEM_CHECK_INTERVAL);

    loop {
        interval.tick().await;

        let state = guardian.system_state.read().get_current_state()?;
        
        // Record system metrics
        guardian
            .metrics
            .record_system_metric(
                "system.health".into(),
                match state.health {
                    SystemHealth::Healthy => 0.0,
                    SystemHealth::Degraded => 1.0,
                    SystemHealth::Critical => 2.0,
                },
                None,
            )
            .await?;

        // Publish system state event
        guardian
            .event_bus
            .publish(Event::new(
                "system.state".into(),
                serde_json::to_value(&state)?,
                EventPriority::High,
            )?)
            .await?;

        debug!(?state, "System state monitored");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_guardian_lifecycle() {
        let config = GuardianConfig {
            temporal_namespace: DEFAULT_TEMPORAL_NAMESPACE.into(),
            metrics_prefix: DEFAULT_METRICS_PREFIX.into(),
            log_level: "debug".into(),
            event_bus_capacity: DEFAULT_EVENT_BUS_CAPACITY,
            monitor_interval: Duration::from_secs(1),
            circuit_breaker_threshold: CIRCUIT_BREAKER_THRESHOLD,
        };

        let guardian = Guardian::new(config).await.unwrap();
        assert!(guardian.start().await.is_ok());
        assert!(guardian.shutdown().await.is_ok());
    }
}