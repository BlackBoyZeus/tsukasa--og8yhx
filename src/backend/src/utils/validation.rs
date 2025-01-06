use lru::LruCache;
use regex::Regex;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};
use validator::{Validate, ValidationError as ValidatorError};

use crate::utils::error::{GuardianError, ErrorCategory, ErrorSeverity};
use crate::utils::metrics::{MetricsCollector, MetricType, MetricPriority};

// Core validation constants
const MAX_INPUT_LENGTH: usize = 4096;
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);
const VALIDATION_CACHE_SIZE: usize = 1000;
const VALIDATION_RATE_LIMIT: u32 = 100;
const DANGEROUS_PATTERNS: [&str; 8] = ["../", "<script>", "--", ";", "/*", "*/", "@@", "${"];

/// Validation result with detailed context
#[derive(Debug, Clone)]
pub struct ValidationResult {
    is_valid: bool,
    errors: Vec<ValidationError>,
    validation_time: Duration,
    security_score: f64,
}

/// Custom validation error type
#[derive(Debug, Clone, Error)]
pub enum ValidationError {
    #[error("Input exceeds maximum length")]
    InputTooLong,
    #[error("Invalid input format: {0}")]
    InvalidFormat(String),
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Validation timeout")]
    Timeout,
}

/// Validation rule with security controls
#[derive(Debug, Clone)]
struct ValidationRule {
    pattern: Regex,
    error_message: String,
    security_level: SecurityLevel,
    priority: ValidationPriority,
}

/// Security levels for validation rules
#[derive(Debug, Clone, Copy, PartialEq)]
enum SecurityLevel {
    Critical,
    High,
    Medium,
    Low,
}

/// Priority levels for validation execution
#[derive(Debug, Clone, Copy, PartialEq)]
enum ValidationPriority {
    Immediate,
    High,
    Normal,
    Low,
}

/// Core validation trait
pub trait Validator: Send + Sync {
    fn validate(&self, input: &str) -> Result<ValidationResult, GuardianError>;
    fn security_level(&self) -> SecurityLevel;
}

/// Primary validation context
#[derive(Debug, Clone)]
pub struct ValidationContext {
    metrics_collector: MetricsCollector,
    validators: Vec<Box<dyn Validator>>,
    validation_rules: HashMap<String, ValidationRule>,
    validation_cache: LruCache<String, ValidationResult>,
    last_validation: Instant,
    rate_limit_counter: u32,
}

impl ValidationContext {
    /// Creates a new validation context with security controls
    pub fn new(metrics_collector: MetricsCollector) -> Self {
        Self {
            metrics_collector,
            validators: Vec::new(),
            validation_rules: HashMap::new(),
            validation_cache: LruCache::new(VALIDATION_CACHE_SIZE),
            last_validation: Instant::now(),
            rate_limit_counter: 0,
        }
    }

    /// Adds a custom validator with security checks
    #[instrument(skip(self, validator))]
    pub fn add_validator(
        &mut self,
        validator: Box<dyn Validator>,
    ) -> Result<(), GuardianError> {
        // Security check for validator
        if !self.verify_validator_security(&validator) {
            return Err(GuardianError::ValidationError {
                context: "Validator failed security verification".into(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        self.validators.push(validator);
        self.metrics_collector.record_metric(
            "guardian.validation.validator_added".into(),
            1.0,
            MetricType::Counter,
            MetricPriority::Medium,
            None,
        )?;

        Ok(())
    }

    /// Validates input with comprehensive security checks
    #[instrument(skip(self, input))]
    pub fn validate<T: AsRef<str>>(&mut self, input: T) -> Result<ValidationResult, GuardianError> {
        let start_time = Instant::now();
        let input = input.as_ref();

        // Rate limiting check
        if !self.check_rate_limit() {
            return Err(GuardianError::ValidationError {
                context: "Validation rate limit exceeded".into(),
                source: None,
                severity: ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Cache check
        if let Some(cached_result) = self.validation_cache.get(input) {
            self.metrics_collector.record_metric(
                "guardian.validation.cache_hit".into(),
                1.0,
                MetricType::Counter,
                MetricPriority::Low,
                None,
            )?;
            return Ok(cached_result.clone());
        }

        // Input length check
        if input.len() > MAX_INPUT_LENGTH {
            return Err(GuardianError::ValidationError {
                context: "Input exceeds maximum length".into(),
                source: None,
                severity: ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Security pattern check
        let mut errors = Vec::new();
        for pattern in DANGEROUS_PATTERNS.iter() {
            if input.contains(pattern) {
                errors.push(ValidationError::SecurityViolation(
                    format!("Dangerous pattern detected: {}", pattern)
                ));
            }
        }

        // Run custom validators
        for validator in &self.validators {
            match validator.validate(input) {
                Ok(result) => {
                    if !result.is_valid {
                        errors.extend(result.errors);
                    }
                }
                Err(e) => {
                    error!("Validator error: {:?}", e);
                    self.metrics_collector.record_metric(
                        "guardian.validation.validator_error".into(),
                        1.0,
                        MetricType::Counter,
                        MetricPriority::High,
                        None,
                    )?;
                }
            }
        }

        let validation_time = start_time.elapsed();
        let security_score = self.calculate_security_score(input, &errors);

        let result = ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            validation_time,
            security_score,
        };

        // Cache result
        self.validation_cache.put(input.to_string(), result.clone());

        // Record metrics
        self.record_validation_metrics(&result)?;

        Ok(result)
    }

    // Helper methods
    fn verify_validator_security(&self, validator: &Box<dyn Validator>) -> bool {
        // Implement security verification logic
        validator.security_level() != SecurityLevel::Low
    }

    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_validation) > Duration::from_secs(1) {
            self.rate_limit_counter = 0;
            self.last_validation = now;
        }
        
        self.rate_limit_counter += 1;
        self.rate_limit_counter <= VALIDATION_RATE_LIMIT
    }

    fn calculate_security_score(&self, input: &str, errors: &[ValidationError]) -> f64 {
        let mut score = 100.0;
        
        // Deduct points for security violations
        score -= (errors.len() as f64) * 10.0;
        
        // Check input entropy
        score -= (input.len() as f64) * 0.01;
        
        score.max(0.0).min(100.0)
    }

    fn record_validation_metrics(&self, result: &ValidationResult) -> Result<(), GuardianError> {
        self.metrics_collector.record_metric(
            "guardian.validation.duration_ms".into(),
            result.validation_time.as_millis() as f64,
            MetricType::Histogram,
            MetricPriority::Medium,
            None,
        )?;

        self.metrics_collector.record_metric(
            "guardian.validation.security_score".into(),
            result.security_score,
            MetricType::Gauge,
            MetricPriority::High,
            None,
        )?;

        if !result.is_valid {
            self.metrics_collector.record_metric(
                "guardian.validation.failures".into(),
                1.0,
                MetricType::Counter,
                MetricPriority::High,
                None,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestValidator;

    impl Validator for TestValidator {
        fn validate(&self, input: &str) -> Result<ValidationResult, GuardianError> {
            Ok(ValidationResult {
                is_valid: !input.contains("invalid"),
                errors: vec![],
                validation_time: Duration::from_millis(1),
                security_score: 100.0,
            })
        }

        fn security_level(&self) -> SecurityLevel {
            SecurityLevel::High
        }
    }

    #[test]
    fn test_validation_context() {
        let metrics_collector = MetricsCollector::new(Default::default()).unwrap();
        let mut context = ValidationContext::new(metrics_collector);
        
        let result = context.validate("valid input").unwrap();
        assert!(result.is_valid);
        
        let result = context.validate("<script>alert('xss')</script>").unwrap();
        assert!(!result.is_valid);
    }
}