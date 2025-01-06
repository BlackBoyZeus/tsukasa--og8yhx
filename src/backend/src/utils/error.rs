use metrics::{counter, histogram};
use serde::Serialize;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{error, info, warn};
use uuid::Uuid;

// Constants for error handling configuration
const RETRY_LIMIT: u32 = 3;
const ERROR_CONTEXT_MAX_LENGTH: usize = 1024;
const ERROR_SAMPLING_RATE: f64 = 0.1;
const MAX_ERROR_CHAIN_LENGTH: usize = 10;
const ERROR_CACHE_SIZE: usize = 1000;

/// Error severity levels for prioritization and handling
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum ErrorSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Categories of errors for classification and metrics
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum ErrorCategory {
    System,
    Security,
    ML,
    Storage,
    Validation,
}

/// Primary error type for the Guardian system
#[derive(Debug, Error, Serialize)]
pub enum GuardianError {
    #[error("System error: {context}")]
    SystemError {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        severity: ErrorSeverity,
        timestamp: OffsetDateTime,
        correlation_id: Uuid,
        category: ErrorCategory,
        retry_count: u32,
    },

    #[error("Security error: {context}")]
    SecurityError {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        severity: ErrorSeverity,
        timestamp: OffsetDateTime,
        correlation_id: Uuid,
        category: ErrorCategory,
        retry_count: u32,
    },

    #[error("ML error: {context}")]
    MLError {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        severity: ErrorSeverity,
        timestamp: OffsetDateTime,
        correlation_id: Uuid,
        category: ErrorCategory,
        retry_count: u32,
    },

    #[error("Storage error: {context}")]
    StorageError {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        severity: ErrorSeverity,
        timestamp: OffsetDateTime,
        correlation_id: Uuid,
        category: ErrorCategory,
        retry_count: u32,
    },

    #[error("Validation error: {context}")]
    ValidationError {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        severity: ErrorSeverity,
        timestamp: OffsetDateTime,
        correlation_id: Uuid,
        category: ErrorCategory,
        retry_count: u32,
    },
}

impl GuardianError {
    /// Adds context to an error while preserving the original error chain
    pub fn with_context<S: Into<String>>(self, context: S) -> Self {
        let context = context.into();
        let context = if context.len() > ERROR_CONTEXT_MAX_LENGTH {
            context[..ERROR_CONTEXT_MAX_LENGTH].to_string()
        } else {
            context
        };

        match self {
            GuardianError::SystemError { source, severity, category, retry_count, .. } => {
                GuardianError::SystemError {
                    context,
                    source,
                    severity,
                    timestamp: OffsetDateTime::now_utc(),
                    correlation_id: Uuid::new_v4(),
                    category,
                    retry_count,
                }
            }
            // Similar pattern for other variants...
            _ => self
        }
    }

    /// Sets the severity level of an error
    pub fn with_severity(self, severity: ErrorSeverity) -> Self {
        match self {
            GuardianError::SystemError { context, source, category, retry_count, .. } => {
                counter!("guardian.error.severity", 1, "severity" => severity.to_string());
                GuardianError::SystemError {
                    context,
                    source,
                    severity,
                    timestamp: OffsetDateTime::now_utc(),
                    correlation_id: Uuid::new_v4(),
                    category,
                    retry_count,
                }
            }
            // Similar pattern for other variants...
            _ => self
        }
    }

    /// Increments the retry count for retryable errors
    pub fn increment_retry(&self) -> Option<Self> {
        if self.retry_count() >= RETRY_LIMIT {
            None
        } else {
            Some(self.clone().with_retry_count(self.retry_count() + 1))
        }
    }

    /// Gets the current retry count
    pub fn retry_count(&self) -> u32 {
        match self {
            GuardianError::SystemError { retry_count, .. } => *retry_count,
            GuardianError::SecurityError { retry_count, .. } => *retry_count,
            GuardianError::MLError { retry_count, .. } => *retry_count,
            GuardianError::StorageError { retry_count, .. } => *retry_count,
            GuardianError::ValidationError { retry_count, .. } => *retry_count,
        }
    }

    /// Sets a specific retry count
    fn with_retry_count(self, count: u32) -> Self {
        match self {
            GuardianError::SystemError { context, source, severity, category, .. } => {
                GuardianError::SystemError {
                    context,
                    source,
                    severity,
                    timestamp: OffsetDateTime::now_utc(),
                    correlation_id: Uuid::new_v4(),
                    category,
                    retry_count: count,
                }
            }
            // Similar pattern for other variants...
            _ => self
        }
    }
}

/// Trait for adding context to errors
pub trait ErrorContext<T, E> {
    /// Adds context to an error
    fn context<C>(self, context: C) -> Result<T, GuardianError>
    where
        C: Into<String>;

    /// Provides the error source
    fn error_source(self) -> Result<T, GuardianError>;
}

/// Type alias for Guardian results
pub type Result<T> = std::result::Result<T, GuardianError>;

/// Logs an error with appropriate severity and context
#[tracing::instrument]
pub fn log_error(error: &GuardianError) {
    match error {
        GuardianError::SystemError { severity: ErrorSeverity::Critical, context, .. } => {
            error!(error = ?error, context = %context, "Critical system error occurred");
        }
        GuardianError::SecurityError { severity: ErrorSeverity::High, context, .. } => {
            error!(error = ?error, context = %context, "High severity security error occurred");
        }
        _ => {
            warn!(error = ?error, "Error occurred");
        }
    }

    record_error_metrics(error);
}

/// Records error metrics for monitoring
#[tracing::instrument]
pub fn record_error_metrics(error: &GuardianError) {
    let category = match error {
        GuardianError::SystemError { category, .. } => category,
        GuardianError::SecurityError { category, .. } => category,
        GuardianError::MLError { category, .. } => category,
        GuardianError::StorageError { category, .. } => category,
        GuardianError::ValidationError { category, .. } => category,
    };

    counter!("guardian.errors.total", 1, "category" => category.to_string());
    histogram!("guardian.errors.retry_count", error.retry_count() as f64);

    if error.retry_count() >= RETRY_LIMIT {
        counter!("guardian.errors.retry_exceeded", 1, "category" => category.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_context() {
        let error = GuardianError::SystemError {
            context: "test error".to_string(),
            source: None,
            severity: ErrorSeverity::High,
            timestamp: OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: ErrorCategory::System,
            retry_count: 0,
        };

        let error_with_context = error.with_context("additional context");
        assert!(matches!(error_with_context, GuardianError::SystemError { .. }));
    }

    #[test]
    fn test_retry_limit() {
        let error = GuardianError::SystemError {
            context: "test error".to_string(),
            source: None,
            severity: ErrorSeverity::High,
            timestamp: OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: ErrorCategory::System,
            retry_count: RETRY_LIMIT,
        };

        assert!(error.increment_retry().is_none());
    }
}