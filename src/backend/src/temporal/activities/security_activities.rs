use std::sync::Arc;
use temporal_sdk::{ActivityOptions, ActivityContext};
use async_trait::async_trait;
use tracing::{debug, error, info, instrument, warn};
use serde::{Serialize, Deserialize};
use metrics::{counter, histogram};

use crate::security::threat_detection::{ThreatDetector, ThreatLevel};
use crate::security::response_engine::{ResponseEngine, ResponseAction, ResponseStatus};
use crate::security::audit::{AuditLogger, AuditEvent, SecurityLevel};
use crate::utils::error::{GuardianError, SecurityError};

// Constants for activity configuration
const ACTIVITY_VERSION: &str = "1.0.0";
const DEFAULT_ACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_BATCH_SIZE: usize = 100;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const CIRCUIT_BREAKER_RESET_TIMEOUT: Duration = Duration::from_secs(300);

/// Configuration for security activities
#[derive(Debug, Clone)]
pub struct ActivityConfig {
    batch_size: usize,
    timeout: Duration,
    heartbeat_interval: Duration,
    circuit_breaker_threshold: u32,
}

impl Default for ActivityConfig {
    fn default() -> Self {
        Self {
            batch_size: MAX_BATCH_SIZE,
            timeout: DEFAULT_ACTIVITY_TIMEOUT,
            heartbeat_interval: HEARTBEAT_INTERVAL,
            circuit_breaker_threshold: CIRCUIT_BREAKER_THRESHOLD,
        }
    }
}

/// Metrics for activity monitoring
#[derive(Debug)]
struct ActivityMetrics {
    success_count: AtomicU64,
    failure_count: AtomicU64,
    last_execution: RwLock<Instant>,
}

/// Circuit breaker for activity protection
#[derive(Debug)]
struct CircuitBreaker {
    failures: AtomicU32,
    last_failure: RwLock<Instant>,
    is_open: AtomicBool,
}

/// Core security activities trait
#[async_trait]
pub trait SecurityActivities {
    async fn detect_threats(&self, ctx: ActivityContext, system_data: SystemData) 
        -> Result<ThreatAnalysis, ActivityError>;
    
    async fn execute_response(&self, ctx: ActivityContext, threat_analysis: ThreatAnalysis) 
        -> Result<ResponseStatus, ActivityError>;
    
    async fn record_audit(&self, ctx: ActivityContext, event: AuditEvent) 
        -> Result<(), ActivityError>;
    
    async fn batch_detect_threats(&self, ctx: ActivityContext, system_data: Vec<SystemData>) 
        -> Result<Vec<ThreatAnalysis>, ActivityError>;
}

/// Implementation of security activities
#[derive(Debug)]
#[async_trait]
pub struct SecurityActivitiesImpl {
    threat_detector: Arc<ThreatDetector>,
    response_engine: Arc<ResponseEngine>,
    audit_logger: Arc<AuditLogger>,
    metrics: Arc<ActivityMetrics>,
    circuit_breaker: Arc<CircuitBreaker>,
    batch_config: BatchConfig,
}

impl SecurityActivitiesImpl {
    /// Creates a new SecurityActivitiesImpl instance
    pub fn new(
        threat_detector: Arc<ThreatDetector>,
        response_engine: Arc<ResponseEngine>,
        audit_logger: Arc<AuditLogger>,
        config: Option<ActivityConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();
        
        Self {
            threat_detector,
            response_engine,
            audit_logger,
            metrics: Arc::new(ActivityMetrics {
                success_count: AtomicU64::new(0),
                failure_count: AtomicU64::new(0),
                last_execution: RwLock::new(Instant::now()),
            }),
            circuit_breaker: Arc::new(CircuitBreaker {
                failures: AtomicU32::new(0),
                last_failure: RwLock::new(Instant::now()),
                is_open: AtomicBool::new(false),
            }),
            batch_config: BatchConfig {
                max_size: config.batch_size,
                timeout: config.timeout,
            },
        }
    }

    /// Creates instance with custom configuration
    pub fn with_config(
        threat_detector: Arc<ThreatDetector>,
        response_engine: Arc<ResponseEngine>,
        audit_logger: Arc<AuditLogger>,
        config: ActivityConfig,
    ) -> Self {
        Self::new(threat_detector, response_engine, audit_logger, Some(config))
    }
}

#[async_trait]
impl SecurityActivities for SecurityActivitiesImpl {
    #[tracing::instrument(skip(self, ctx))]
    #[activity(retention_period = "24 hours")]
    async fn detect_threats(
        &self,
        ctx: ActivityContext,
        system_data: SystemData,
    ) -> Result<ThreatAnalysis, ActivityError> {
        // Validate activity context
        validate_activity_context(&ctx)?;

        // Check circuit breaker
        if self.circuit_breaker.is_open.load(Ordering::SeqCst) {
            return Err(ActivityError::CircuitBreakerOpen);
        }

        let start_time = Instant::now();

        // Record activity start
        counter!("guardian.activity.detect_threats.start", 1);

        // Execute threat detection
        let result = tokio::time::timeout(
            self.batch_config.timeout,
            self.threat_detector.analyze_threat(system_data)
        ).await.map_err(|_| ActivityError::Timeout)??;

        // Update metrics
        self.metrics.success_count.fetch_add(1, Ordering::SeqCst);
        *self.metrics.last_execution.write().await = Instant::now();
        
        histogram!(
            "guardian.activity.detect_threats.duration",
            start_time.elapsed().as_secs_f64()
        );

        Ok(result)
    }

    #[tracing::instrument(skip(self, ctx))]
    #[activity(heartbeat_timeout = "5 seconds")]
    async fn execute_response(
        &self,
        ctx: ActivityContext,
        threat_analysis: ThreatAnalysis,
    ) -> Result<ResponseStatus, ActivityError> {
        validate_activity_context(&ctx)?;

        if self.circuit_breaker.is_open.load(Ordering::SeqCst) {
            return Err(ActivityError::CircuitBreakerOpen);
        }

        let start_time = Instant::now();
        counter!("guardian.activity.execute_response.start", 1);

        // Execute response with heartbeat
        let result = self.response_engine.execute_response(threat_analysis).await?;

        // Record audit event
        self.audit_logger.record_event(AuditEvent::new(
            "security.response.executed",
            SecurityLevel::High,
            "response_engine",
            Some(result.correlation_id.to_string()),
        )).await?;

        histogram!(
            "guardian.activity.execute_response.duration",
            start_time.elapsed().as_secs_f64()
        );

        Ok(result)
    }

    #[tracing::instrument(skip(self, ctx))]
    #[activity(retention_period = "90 days")]
    async fn record_audit(
        &self,
        ctx: ActivityContext,
        event: AuditEvent,
    ) -> Result<(), ActivityError> {
        validate_activity_context(&ctx)?;
        
        let start_time = Instant::now();
        counter!("guardian.activity.record_audit.start", 1);

        self.audit_logger.record_event(event).await?;

        histogram!(
            "guardian.activity.record_audit.duration",
            start_time.elapsed().as_secs_f64()
        );

        Ok(())
    }

    #[tracing::instrument(skip(self, ctx))]
    #[activity(heartbeat_timeout = "10 seconds")]
    async fn batch_detect_threats(
        &self,
        ctx: ActivityContext,
        system_data: Vec<SystemData>,
    ) -> Result<Vec<ThreatAnalysis>, ActivityError> {
        validate_activity_context(&ctx)?;

        if system_data.len() > self.batch_config.max_size {
            return Err(ActivityError::BatchSizeExceeded);
        }

        let start_time = Instant::now();
        counter!("guardian.activity.batch_detect_threats.start", 1);

        let results = self.threat_detector.batch_analyze(system_data).await?;

        histogram!(
            "guardian.activity.batch_detect_threats.duration",
            start_time.elapsed().as_secs_f64()
        );

        Ok(results)
    }
}

/// Validates the Temporal activity context
#[tracing::instrument]
fn validate_activity_context(ctx: &ActivityContext) -> Result<(), ActivityError> {
    if ctx.info().timeout.is_none() {
        return Err(ActivityError::InvalidContext("Missing timeout".into()));
    }

    if ctx.info().attempt > 3 {
        return Err(ActivityError::MaxRetriesExceeded);
    }

    Ok(())
}