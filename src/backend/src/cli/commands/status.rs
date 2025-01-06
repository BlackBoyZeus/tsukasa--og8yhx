use std::sync::Arc;
use std::time::Duration;
use clap::{Arg, Command as ClapCommand}; // v4.0
use serde_json::json; // v1.0
use tracing::{debug, error, info, instrument, warn}; // v0.1
use tokio::sync::{Mutex, RwLock};

use crate::cli::commands::{Command, AccessLevel};
use crate::utils::error::GuardianError;
use crate::core::system_state::{SystemState, SystemHealth};
use crate::core::metrics::{SystemMetrics, PerformanceMetrics};

// Constants for status command configuration
const COMMAND_NAME: &str = "status";
const DEFAULT_OUTPUT_FORMAT: OutputFormat = OutputFormat::Text;
const DEFAULT_SAMPLING_RATE: f64 = 0.1;
const MAX_BATCH_SIZE: usize = 1000;
const METRICS_BUFFER_SIZE: usize = 10000;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);

/// Output format options for status display
#[derive(Debug, Clone, PartialEq)]
enum OutputFormat {
    Text,
    Json,
    Compact,
}

/// Enhanced metrics buffer for optimized collection
#[derive(Debug)]
struct MetricsBuffer {
    metrics: Vec<PerformanceMetrics>,
    last_flush: std::time::Instant,
    capacity: usize,
}

/// Circuit breaker for fault tolerance
#[derive(Debug)]
struct CircuitBreaker {
    failures: u32,
    last_failure: std::time::Instant,
    threshold: u32,
    reset_timeout: Duration,
}

/// Enhanced status command implementation
#[derive(Debug)]
pub struct StatusCommand {
    system_state: Arc<SystemState>,
    metrics: Arc<SystemMetrics>,
    buffer: Mutex<MetricsBuffer>,
    breaker: RwLock<CircuitBreaker>,
    access_control: AccessLevel,
}

impl StatusCommand {
    /// Creates a new StatusCommand instance with enhanced features
    pub fn new(system_state: Arc<SystemState>, metrics: Arc<SystemMetrics>) -> Self {
        Self {
            system_state,
            metrics,
            buffer: Mutex::new(MetricsBuffer {
                metrics: Vec::with_capacity(METRICS_BUFFER_SIZE),
                last_flush: std::time::Instant::now(),
                capacity: METRICS_BUFFER_SIZE,
            }),
            breaker: RwLock::new(CircuitBreaker {
                failures: 0,
                last_failure: std::time::Instant::now(),
                threshold: 5,
                reset_timeout: Duration::from_secs(60),
            }),
            access_control: AccessLevel::Operator,
        }
    }

    /// Formats system status with enhanced security validation
    #[instrument(skip(self))]
    async fn format_output(&self, format: OutputFormat) -> Result<String, GuardianError> {
        let health = self.system_state.health_status.read().await;
        let metrics = self.system_state.resource_metrics.read().await;
        let security = self.system_state.security_status.read().await;

        match format {
            OutputFormat::Json => {
                Ok(json!({
                    "health": {
                        "status": format!("{:?}", *health),
                        "last_update": chrono::Utc::now().timestamp()
                    },
                    "resources": {
                        "cpu_usage": metrics.cpu_usage,
                        "memory_usage": metrics.memory_usage,
                        "system_load": metrics.system_load,
                        "uptime_seconds": metrics.uptime_seconds
                    },
                    "security": {
                        "active_threats": security.active_threats,
                        "security_level": security.security_level,
                        "is_lockdown": security.is_lockdown
                    }
                }).to_string())
            },
            OutputFormat::Text => {
                Ok(format!(
                    "System Status:\n\
                     Health: {:?}\n\
                     CPU Usage: {:.1}%\n\
                     Memory Usage: {:.1}%\n\
                     System Load: {:.2}\n\
                     Active Threats: {}\n\
                     Security Level: {}\n\
                     Lockdown Status: {}",
                    *health,
                    metrics.cpu_usage,
                    metrics.memory_usage,
                    metrics.system_load,
                    security.active_threats,
                    security.security_level,
                    if security.is_lockdown { "ACTIVE" } else { "Inactive" }
                ))
            },
            OutputFormat::Compact => {
                Ok(format!(
                    "Health:{:?} CPU:{:.1}% Mem:{:.1}% Load:{:.2} Threats:{}",
                    *health,
                    metrics.cpu_usage,
                    metrics.memory_usage,
                    metrics.system_load,
                    security.active_threats
                ))
            }
        }
    }

    /// Collects system metrics with optimized performance
    #[instrument(skip(self))]
    async fn collect_metrics(&self) -> Result<PerformanceMetrics, GuardianError> {
        let mut buffer = self.buffer.lock().await;
        let metrics = self.metrics.collect_performance_metrics().await?;

        buffer.metrics.push(metrics.clone());
        
        if buffer.metrics.len() >= buffer.capacity || 
           buffer.last_flush.elapsed() >= Duration::from_secs(5) {
            self.flush_metrics_buffer(&mut buffer).await?;
        }

        Ok(metrics)
    }

    /// Flushes the metrics buffer with batching
    async fn flush_metrics_buffer(&self, buffer: &mut MetricsBuffer) -> Result<(), GuardianError> {
        let metrics_batch = std::mem::replace(&mut buffer.metrics, Vec::with_capacity(buffer.capacity));
        buffer.last_flush = std::time::Instant::now();

        for chunk in metrics_batch.chunks(MAX_BATCH_SIZE) {
            if let Err(e) = self.metrics.record_system_metrics(chunk.to_vec()).await {
                warn!(error = ?e, "Failed to record metrics batch");
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Command for StatusCommand {
    /// Returns the command name
    fn name(&self) -> &'static str {
        COMMAND_NAME
    }

    /// Returns required access level
    fn required_access(&self) -> AccessLevel {
        self.access_control
    }

    /// Configures command arguments
    fn configure(&self) -> ClapCommand {
        ClapCommand::new(COMMAND_NAME)
            .about("Display system status and health metrics")
            .arg(
                Arg::new("format")
                    .short('f')
                    .long("format")
                    .value_parser(["text", "json", "compact"])
                    .default_value("text")
                    .help("Output format")
            )
    }

    /// Executes the status command with enhanced security and performance
    #[instrument(skip(self, args))]
    async fn execute(&self, args: &clap::ArgMatches) -> Result<(), GuardianError> {
        // Check circuit breaker
        let breaker = self.breaker.read().await;
        if breaker.failures >= breaker.threshold {
            if breaker.last_failure.elapsed() < breaker.reset_timeout {
                return Err(GuardianError::SystemError("Circuit breaker is open".to_string()));
            }
        }
        drop(breaker);

        // Parse output format
        let format = match args.get_one::<String>("format").map(|s| s.as_str()) {
            Some("json") => OutputFormat::Json,
            Some("compact") => OutputFormat::Compact,
            _ => OutputFormat::Text,
        };

        // Collect and validate metrics
        let metrics = self.collect_metrics().await?;
        if metrics.cpu_usage > 95.0 || metrics.memory_usage > 95.0 {
            warn!(
                cpu = %metrics.cpu_usage,
                memory = %metrics.memory_usage,
                "System resources critically high"
            );
        }

        // Format and display output
        let output = self.format_output(format).await?;
        println!("{}", output);

        // Update metrics and status
        if let Err(e) = self.metrics.record_system_metrics(vec![metrics]).await {
            let mut breaker = self.breaker.write().await;
            breaker.failures += 1;
            breaker.last_failure = std::time::Instant::now();
            error!(error = ?e, "Failed to record system metrics");
        }

        debug!("Status command executed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::metrics::init_core_metrics;
    use crate::utils::metrics::MetricsConfig;

    #[tokio::test]
    async fn test_status_command_execution() {
        let metrics_config = MetricsConfig::default();
        let metrics = Arc::new(init_core_metrics(metrics_config).await.unwrap());
        let system_state = Arc::new(SystemState::new(Arc::new(EventBus::new())).await.unwrap());
        
        let command = StatusCommand::new(system_state, metrics);
        let args = command.configure().get_matches_from(vec!["status"]);
        
        assert!(command.execute(&args).await.is_ok());
    }

    #[tokio::test]
    async fn test_output_formats() {
        let metrics_config = MetricsConfig::default();
        let metrics = Arc::new(init_core_metrics(metrics_config).await.unwrap());
        let system_state = Arc::new(SystemState::new(Arc::new(EventBus::new())).await.unwrap());
        
        let command = StatusCommand::new(system_state, metrics);

        // Test JSON format
        let json_output = command.format_output(OutputFormat::Json).await.unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&json_output).is_ok());

        // Test text format
        let text_output = command.format_output(OutputFormat::Text).await.unwrap();
        assert!(text_output.contains("System Status"));

        // Test compact format
        let compact_output = command.format_output(OutputFormat::Compact).await.unwrap();
        assert!(compact_output.contains("CPU:"));
    }
}