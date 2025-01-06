use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::Duration,
};
use tokio::time;
use tracing::{debug, error, info, instrument, warn};

use crate::utils::error::GuardianError;
use crate::utils::metrics::MetricsCollector;
use crate::core::event_bus::EventBus;

// Constants for state management configuration
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const CPU_USAGE_THRESHOLD: f64 = 80.0;
const MEMORY_USAGE_THRESHOLD: f64 = 85.0;
const STATE_HISTORY_CAPACITY: usize = 1000;
const LOCK_ACQUISITION_TIMEOUT: Duration = Duration::from_millis(100);
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const STATE_VALIDATION_TIMEOUT: Duration = Duration::from_millis(50);

/// System health status indicators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SystemHealth {
    Healthy,
    Degraded,
    Critical,
}

/// Circuit breaker for state operations
#[derive(Debug, Clone)]
struct CircuitBreaker {
    failures: u32,
    last_failure: DateTime<Utc>,
    is_open: bool,
}

/// State validation rule definition
#[derive(Debug, Clone)]
struct StateValidationRule {
    name: String,
    validator: Box<dyn Fn(&SystemState) -> bool + Send + Sync>,
    severity: SystemHealth,
}

/// Snapshot of system state for history tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateSnapshot {
    state: SystemState,
    timestamp: DateTime<Utc>,
}

/// Configuration for state management
#[derive(Debug, Clone)]
struct StateConfig {
    history_capacity: usize,
    validation_timeout: Duration,
    health_check_interval: Duration,
}

/// Core system state management structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    health: SystemHealth,
    cpu_usage: f64,
    memory_usage: f64,
    active_threats: u32,
    last_update: DateTime<Utc>,
    #[serde(skip)]
    state_history: VecDeque<StateSnapshot>,
    #[serde(skip)]
    circuit_breaker: CircuitBreaker,
    #[serde(skip)]
    validation_rules: Vec<StateValidationRule>,
}

impl SystemState {
    /// Creates a new SystemState instance with optimized initial configuration
    pub fn new(metrics: MetricsCollector, event_bus: EventBus, config: StateConfig) -> Result<Arc<RwLock<Self>>, GuardianError> {
        let state = Arc::new(RwLock::new(Self {
            health: SystemHealth::Healthy,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            active_threats: 0,
            last_update: Utc::now(),
            state_history: VecDeque::with_capacity(config.history_capacity),
            circuit_breaker: CircuitBreaker {
                failures: 0,
                last_failure: Utc::now(),
                is_open: false,
            },
            validation_rules: Self::default_validation_rules(),
        }));

        // Start background health monitoring
        let state_clone = Arc::clone(&state);
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(config.health_check_interval);
            loop {
                interval.tick().await;
                if let Err(e) = monitor_system_health(Arc::clone(&state_clone), metrics_clone.clone()).await {
                    error!(?e, "Failed to monitor system health");
                }
            }
        });

        Ok(state)
    }

    /// Retrieves the current system state with optimized read access
    #[instrument(skip(self))]
    pub fn get_current_state(&self) -> Result<SystemState, GuardianError> {
        if self.circuit_breaker.is_open {
            return Err(GuardianError::SystemError {
                context: "Circuit breaker is open".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            });
        }

        Ok(self.clone())
    }

    /// Updates the system state with new values using optimized write patterns
    #[instrument(skip(self, new_state))]
    pub async fn update_state(&mut self, new_state: SystemState) -> Result<(), GuardianError> {
        // Validate new state
        for rule in &self.validation_rules {
            if !(rule.validator)(&new_state) {
                return Err(GuardianError::ValidationError {
                    context: format!("State validation failed: {}", rule.name),
                    source: None,
                    severity: crate::utils::error::ErrorSeverity::High,
                    timestamp: time::OffsetDateTime::now_utc(),
                    correlation_id: uuid::Uuid::new_v4(),
                    category: crate::utils::error::ErrorCategory::Validation,
                    retry_count: 0,
                });
            }
        }

        // Create state snapshot
        let snapshot = StateSnapshot {
            state: self.clone(),
            timestamp: Utc::now(),
        };

        // Update state values
        self.health = new_state.health;
        self.cpu_usage = new_state.cpu_usage;
        self.memory_usage = new_state.memory_usage;
        self.active_threats = new_state.active_threats;
        self.last_update = Utc::now();

        // Update history
        if self.state_history.len() >= STATE_HISTORY_CAPACITY {
            self.state_history.pop_front();
        }
        self.state_history.push_back(snapshot);

        Ok(())
    }

    /// Creates default validation rules for state management
    fn default_validation_rules() -> Vec<StateValidationRule> {
        vec![
            StateValidationRule {
                name: "CPU Usage Range".into(),
                validator: Box::new(|state| (0.0..=100.0).contains(&state.cpu_usage)),
                severity: SystemHealth::Critical,
            },
            StateValidationRule {
                name: "Memory Usage Range".into(),
                validator: Box::new(|state| (0.0..=100.0).contains(&state.memory_usage)),
                severity: SystemHealth::Critical,
            },
            StateValidationRule {
                name: "Active Threats Sanity".into(),
                validator: Box::new(|state| state.active_threats < 1000),
                severity: SystemHealth::High,
            },
        ]
    }
}

/// Background task monitoring system health metrics with optimized performance
#[instrument(skip(state, metrics))]
async fn monitor_system_health(
    state: Arc<RwLock<SystemState>>,
    metrics: MetricsCollector,
) -> Result<(), GuardianError> {
    let mut write_guard = state.write();
    
    // Update health status based on metrics
    let new_health = if write_guard.cpu_usage >= CPU_USAGE_THRESHOLD || 
                       write_guard.memory_usage >= MEMORY_USAGE_THRESHOLD {
        SystemHealth::Critical
    } else if write_guard.cpu_usage >= CPU_USAGE_THRESHOLD * 0.8 || 
              write_guard.memory_usage >= MEMORY_USAGE_THRESHOLD * 0.8 {
        SystemHealth::Degraded
    } else {
        SystemHealth::Healthy
    };

    // Record metrics
    metrics.record_metric(
        "system.health".into(),
        match new_health {
            SystemHealth::Healthy => 0.0,
            SystemHealth::Degraded => 1.0,
            SystemHealth::Critical => 2.0,
        },
        crate::utils::metrics::MetricType::Gauge,
        crate::utils::metrics::MetricPriority::High,
        None,
    )?;

    // Update state if health changed
    if write_guard.health != new_health {
        write_guard.health = new_health;
        info!(?new_health, "System health status changed");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::metrics::MetricsConfig;

    #[tokio::test]
    async fn test_system_state_updates() {
        let metrics_config = MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(100),
            flush_interval: Some(Duration::from_secs(1)),
            sampling_rates: None,
        };

        let metrics = MetricsCollector::new(metrics_config).unwrap();
        let event_bus = EventBus::new(metrics.clone()).unwrap();
        
        let state_config = StateConfig {
            history_capacity: STATE_HISTORY_CAPACITY,
            validation_timeout: STATE_VALIDATION_TIMEOUT,
            health_check_interval: HEALTH_CHECK_INTERVAL,
        };

        let state = SystemState::new(metrics, event_bus, state_config).unwrap();
        
        let mut write_guard = state.write();
        let new_state = SystemState {
            health: SystemHealth::Healthy,
            cpu_usage: 50.0,
            memory_usage: 60.0,
            active_threats: 0,
            last_update: Utc::now(),
            state_history: VecDeque::new(),
            circuit_breaker: CircuitBreaker {
                failures: 0,
                last_failure: Utc::now(),
                is_open: false,
            },
            validation_rules: Vec::new(),
        };

        assert!(write_guard.update_state(new_state).await.is_ok());
    }
}