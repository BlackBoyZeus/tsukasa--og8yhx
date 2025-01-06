use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{error, info, warn, instrument};
use uuid::Uuid;

use crate::utils::error::{GuardianError, SecurityError};
use crate::utils::logging::{LogConfig, init_logging};

// Core audit constants
const MAX_AUDIT_EVENT_SIZE: usize = 4096;
const AUDIT_RETENTION_DAYS: u32 = 90;
const MAX_RETRY_ATTEMPTS: u32 = 3;
const AUDIT_SAMPLING_RATE: f64 = 1.0;
const CRITICAL_ALERT_THRESHOLD: u32 = 100;

/// Security levels for audit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityLevel {
    Critical,
    High,
    Medium,
    Low,
}

/// Represents a security audit event with comprehensive metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    id: Uuid,
    event_type: String,
    timestamp: DateTime<Utc>,
    source: String,
    severity: SecurityLevel,
    data: serde_json::Value,
    correlation_id: Option<String>,
    tags: HashMap<String, String>,
}

impl AuditEvent {
    /// Creates a new audit event with required fields
    pub fn new(
        event_type: String,
        severity: SecurityLevel,
        source: String,
        correlation_id: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type,
            timestamp: Utc::now(),
            source,
            severity,
            data: serde_json::Value::Null,
            correlation_id,
            tags: HashMap::new(),
        }
    }

    /// Adds structured data to the audit event
    pub fn with_data(mut self, data: serde_json::Value) -> Result<Self, GuardianError> {
        // Validate data size
        let data_size = serde_json::to_string(&data)
            .map_err(|e| GuardianError::SecurityError {
                context: "Failed to serialize audit data".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Security,
                retry_count: 0,
            })?
            .len();

        if data_size > MAX_AUDIT_EVENT_SIZE {
            return Err(GuardianError::SecurityError {
                context: "Audit event data exceeds maximum size".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Security,
                retry_count: 0,
            });
        }

        self.data = data;
        Ok(self)
    }

    /// Adds tags for better event categorization
    pub fn with_tags(mut self, tags: HashMap<String, String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Statistics for audit logging operations
#[derive(Debug, Clone, Serialize)]
struct AuditStats {
    events_processed: u64,
    events_failed: u64,
    last_event_timestamp: DateTime<Utc>,
    critical_events_count: u32,
    storage_usage: f64,
}

/// Retention policy for audit logs
#[derive(Debug, Clone)]
struct RetentionPolicy {
    retention_days: u32,
    max_storage_size: u64,
    compression_enabled: bool,
}

/// Core audit logging functionality
pub struct AuditLogger {
    config: LogConfig,
    stats: Arc<Mutex<AuditStats>>,
    freebsd_audit: Arc<Mutex<FreeBSDAudit>>,
    metrics: Arc<Mutex<MetricsCollector>>,
    alert_manager: AlertManager,
    retention_policy: RetentionPolicy,
}

impl AuditLogger {
    /// Creates a new AuditLogger instance
    pub fn new(
        config: LogConfig,
        retention_policy: RetentionPolicy,
        alert_config: AlertConfig,
    ) -> Result<Self, GuardianError> {
        // Initialize logging subsystem
        init_logging(config.clone())?;

        // Initialize FreeBSD audit subsystem
        let freebsd_audit = FreeBSDAudit::new()?;

        // Initialize metrics collector
        let metrics = MetricsCollector::new(MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(1000),
            flush_interval: Some(Duration::from_secs(60)),
            sampling_rates: None,
        })?;

        Ok(Self {
            config,
            stats: Arc::new(Mutex::new(AuditStats {
                events_processed: 0,
                events_failed: 0,
                last_event_timestamp: Utc::now(),
                critical_events_count: 0,
                storage_usage: 0.0,
            })),
            freebsd_audit: Arc::new(Mutex::new(freebsd_audit)),
            metrics: Arc::new(Mutex::new(metrics)),
            alert_manager: AlertManager::new(alert_config)?,
            retention_policy,
        })
    }

    /// Records an audit event securely
    #[instrument(skip(self, event))]
    pub async fn record_event(&self, event: AuditEvent) -> Result<(), GuardianError> {
        // Apply sampling if configured
        if rand::random::<f64>() > AUDIT_SAMPLING_RATE {
            return Ok(());
        }

        // Update statistics
        let mut stats = self.stats.lock().map_err(|e| GuardianError::SecurityError {
            context: "Failed to lock audit stats".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        stats.events_processed += 1;
        stats.last_event_timestamp = event.timestamp;

        if event.severity == SecurityLevel::Critical {
            stats.critical_events_count += 1;
        }

        // Write to FreeBSD audit subsystem
        let mut freebsd_audit = self.freebsd_audit.lock().map_err(|e| GuardianError::SecurityError {
            context: "Failed to lock FreeBSD audit".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        freebsd_audit.write_event(&event)?;

        // Record metrics
        let mut metrics = self.metrics.lock().map_err(|e| GuardianError::SecurityError {
            context: "Failed to lock metrics collector".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        metrics.record_metric(
            format!("guardian.audit.events.{}", event.severity.to_string().to_lowercase()),
            1.0,
            MetricType::Counter,
            MetricPriority::High,
            Some(event.tags.clone()),
        )?;

        // Check alert conditions
        if stats.critical_events_count >= CRITICAL_ALERT_THRESHOLD {
            self.alert_manager.trigger_alert(
                "High number of critical security events",
                &event,
                AlertPriority::High,
            )?;
        }

        Ok(())
    }

    /// Retrieves current audit statistics
    pub fn get_stats(&self) -> Result<AuditStats, GuardianError> {
        self.stats.lock()
            .map_err(|e| GuardianError::SecurityError {
                context: "Failed to lock audit stats".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Security,
                retry_count: 0,
            })
            .map(|stats| stats.clone())
    }

    /// Rotates audit logs based on retention policy
    #[instrument(skip(self))]
    pub async fn rotate_logs(&self) -> Result<(), GuardianError> {
        let mut freebsd_audit = self.freebsd_audit.lock().map_err(|e| GuardianError::SecurityError {
            context: "Failed to lock FreeBSD audit".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        freebsd_audit.rotate_logs(self.retention_policy.retention_days)?;

        info!("Audit logs rotated successfully");
        Ok(())
    }

    /// Checks the health of the audit subsystem
    pub fn check_health(&self) -> Result<bool, GuardianError> {
        let stats = self.get_stats()?;
        let freebsd_audit = self.freebsd_audit.lock().map_err(|e| GuardianError::SecurityError {
            context: "Failed to lock FreeBSD audit".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::Security,
            retry_count: 0,
        })?;

        Ok(freebsd_audit.is_healthy() && stats.storage_usage < 90.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_audit_event_creation() {
        let event = AuditEvent::new(
            "security.login".into(),
            SecurityLevel::High,
            "auth_service".into(),
            Some("test-correlation-id".into()),
        );

        assert_eq!(event.event_type, "security.login");
        assert_eq!(event.severity, SecurityLevel::High);
        assert_eq!(event.source, "auth_service");
    }

    #[tokio::test]
    async fn test_audit_event_with_data() {
        let event = AuditEvent::new(
            "security.access".into(),
            SecurityLevel::Medium,
            "file_service".into(),
            None,
        );

        let data = serde_json::json!({
            "file": "sensitive.txt",
            "action": "read",
            "user": "test_user"
        });

        let event_with_data = event.with_data(data).unwrap();
        assert!(event_with_data.data.is_object());
    }

    #[tokio::test]
    async fn test_audit_logger_health_check() {
        let config = LogConfig::default();
        let retention_policy = RetentionPolicy {
            retention_days: AUDIT_RETENTION_DAYS,
            max_storage_size: 1024 * 1024 * 1024,
            compression_enabled: true,
        };
        let alert_config = AlertConfig::default();

        let logger = AuditLogger::new(config, retention_policy, alert_config).unwrap();
        assert!(logger.check_health().unwrap());
    }
}