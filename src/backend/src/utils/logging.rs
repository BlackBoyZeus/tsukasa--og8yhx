use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::{info, warn, error, Level, Metadata, Subscriber};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    fmt::{self, time::UtcTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};
use uuid::Uuid;

use crate::utils::error::{GuardianError, ErrorCategory};
use crate::utils::metrics::{MetricsCollector, MetricType, MetricPriority};

// Constants for logging configuration
const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;
const MAX_LOG_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB
const LOG_ROTATION_DAYS: u32 = 30;
const DEFAULT_BUFFER_SIZE: usize = 8192;
const SECURITY_LOG_PREFIX: &str = "SECURITY-";
const MAX_CORRELATION_ID_LENGTH: usize = 64;

/// Log levels supported by the system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => Level::ERROR,
            LogLevel::Warn => Level::WARN,
            LogLevel::Info => Level::INFO,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Trace => Level::TRACE,
        }
    }
}

/// Configuration structure for the logging subsystem
#[derive(Debug, Clone, Serialize)]
pub struct LogConfig {
    level: LogLevel,
    file_path: String,
    security_audit_path: String,
    json_format: bool,
    max_file_size: usize,
    rotation_days: u32,
    buffer_size: usize,
    enable_encryption: bool,
    enable_metrics: bool,
    correlation_id_header: String,
    sanitization_rules: HashMap<String, String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: DEFAULT_LOG_LEVEL,
            file_path: "logs/guardian.log".to_string(),
            security_audit_path: "logs/security-audit.log".to_string(),
            json_format: true,
            max_file_size: MAX_LOG_FILE_SIZE,
            rotation_days: LOG_ROTATION_DAYS,
            buffer_size: DEFAULT_BUFFER_SIZE,
            enable_encryption: true,
            enable_metrics: true,
            correlation_id_header: "X-Correlation-ID".to_string(),
            sanitization_rules: HashMap::new(),
        }
    }
}

impl LogConfig {
    /// Creates a new LogConfig instance with security-focused defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures security audit logging settings
    pub fn with_security_audit(mut self, audit_path: String, encryption_enabled: bool) -> Self {
        self.security_audit_path = audit_path;
        self.enable_encryption = encryption_enabled;
        self
    }

    /// Configures performance-related logging settings
    pub fn with_performance_settings(mut self, buffer_size: usize, enable_metrics: bool) -> Self {
        self.buffer_size = buffer_size;
        self.enable_metrics = enable_metrics;
        self
    }
}

/// Security event context for audit logging
#[derive(Debug, Clone, Serialize)]
struct SecurityContext {
    correlation_id: Uuid,
    timestamp: OffsetDateTime,
    severity: String,
    source: String,
    user_id: Option<String>,
    ip_address: Option<String>,
    additional_context: HashMap<String, String>,
}

/// Initializes the logging subsystem with enhanced security and performance features
pub fn init_logging(config: LogConfig) -> Result<(), GuardianError> {
    // Validate paths and create directories if needed
    let log_path = PathBuf::from(&config.file_path);
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| GuardianError::SystemError {
            context: "Failed to create log directory".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: ErrorCategory::System,
            retry_count: 0,
        })?;
    }

    // Configure file appenders
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,
        log_path.parent().unwrap(),
        log_path.file_name().unwrap().to_str().unwrap(),
    );

    let security_appender = RollingFileAppender::new(
        Rotation::DAILY,
        PathBuf::from(&config.security_audit_path).parent().unwrap(),
        PathBuf::from(&config.security_audit_path).file_name().unwrap().to_str().unwrap(),
    );

    // Create the subscriber with multiple layers
    let subscriber = tracing_subscriber::registry()
        .with(
            fmt::Layer::new()
                .with_writer(file_appender)
                .with_timer(UtcTime::rfc_3339())
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .with_json(config.json_format)
        )
        .with(
            fmt::Layer::new()
                .with_writer(security_appender)
                .with_timer(UtcTime::rfc_3339())
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .with_json(true)
                .with_filter(|metadata: &Metadata| {
                    metadata.target().starts_with(SECURITY_LOG_PREFIX)
                })
        );

    // Initialize the subscriber
    subscriber.init();

    info!(
        target: "guardian_logging",
        "Logging system initialized with level {:?}",
        config.level
    );

    Ok(())
}

/// Logs security-related events with enhanced context and metrics
#[tracing::instrument]
pub fn log_security_event(
    event: &str,
    context: SecurityContext,
    metrics_collector: Option<&MetricsCollector>,
) -> Result<(), GuardianError> {
    let event = sanitize_log_data(event, &Default::default());

    // Create structured security log entry
    let log_entry = serde_json::json!({
        "event_type": "security",
        "event": event,
        "correlation_id": context.correlation_id.to_string(),
        "timestamp": context.timestamp,
        "severity": context.severity,
        "source": context.source,
        "user_id": context.user_id,
        "ip_address": context.ip_address,
        "additional_context": context.additional_context,
    });

    // Log the security event
    info!(
        target: "SECURITY-AUDIT",
        message = %event,
        correlation_id = %context.correlation_id,
        security_context = ?log_entry
    );

    // Record security metric if metrics are enabled
    if let Some(collector) = metrics_collector {
        let mut tags = HashMap::new();
        tags.insert("severity".to_string(), context.severity.clone());
        tags.insert("source".to_string(), context.source.clone());

        collector.record_metric(
            "guardian.security.events".into(),
            1.0,
            MetricType::Counter,
            MetricPriority::High,
            Some(tags),
        )?;
    }

    Ok(())
}

/// Sanitizes log data to prevent log injection attacks
fn sanitize_log_data(data: &str, rules: &HashMap<String, String>) -> String {
    let mut sanitized = data.to_string();
    
    // Apply custom sanitization rules
    for (pattern, replacement) in rules {
        sanitized = sanitized.replace(pattern, replacement);
    }

    // Remove control characters and normalize whitespace
    sanitized
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            let config = LogConfig::new()
                .with_security_audit("logs/test-security.log".into(), false)
                .with_performance_settings(1024, false);
            init_logging(config).unwrap();
        });
    }

    #[test]
    fn test_log_security_event() {
        setup();

        let context = SecurityContext {
            correlation_id: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
            severity: "HIGH".to_string(),
            source: "test".to_string(),
            user_id: Some("test-user".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            additional_context: HashMap::new(),
        };

        let result = log_security_event("Test security event", context, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sanitize_log_data() {
        let mut rules = HashMap::new();
        rules.insert("password=\\w+".to_string(), "password=*****".to_string());

        let input = "User login failed: password=secret123";
        let sanitized = sanitize_log_data(input, &rules);
        assert!(!sanitized.contains("secret123"));
    }
}