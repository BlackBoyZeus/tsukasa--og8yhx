use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, instrument, warn};
use metrics::{counter, histogram};

use crate::security::threat_detection::ThreatDetector;
use crate::security::response_engine::ResponseEngine;
use crate::utils::error::{GuardianError, SecurityError};

// Import the generated gRPC code
tonic::include_proto!("guardian.security.v1");

// Constants for service configuration
const SERVICE_VERSION: &str = "1.0.0";
const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CONCURRENT_REQUESTS: usize = 1000;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Rate limiter for request throttling
#[derive(Debug)]
struct RateLimiter {
    window_start: RwLock<Instant>,
    request_count: RwLock<usize>,
    max_requests: usize,
    window_duration: Duration,
}

impl RateLimiter {
    fn new(max_requests: usize, window_duration: Duration) -> Self {
        Self {
            window_start: RwLock::new(Instant::now()),
            request_count: RwLock::new(0),
            max_requests,
            window_duration,
        }
    }

    async fn check_rate_limit(&self) -> Result<(), Status> {
        let mut window_start = self.window_start.write();
        let mut request_count = self.request_count.write();

        let now = Instant::now();
        if now.duration_since(*window_start) >= self.window_duration {
            *window_start = now;
            *request_count = 0;
        }

        if *request_count >= self.max_requests {
            return Err(Status::resource_exhausted("Rate limit exceeded"));
        }

        *request_count += 1;
        Ok(())
    }
}

/// Metrics recorder for service telemetry
#[derive(Debug)]
struct MetricsRecorder {
    prefix: String,
}

impl MetricsRecorder {
    fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }

    fn record_request_latency(&self, method: &str, duration: Duration) {
        histogram!(
            format!("{}.request.latency", self.prefix),
            duration.as_secs_f64(),
            "method" => method.to_string()
        );
    }

    fn record_request_count(&self, method: &str, status: &str) {
        counter!(
            format!("{}.request.count", self.prefix),
            1,
            "method" => method.to_string(),
            "status" => status.to_string()
        );
    }
}

#[derive(Debug)]
pub struct GuardianSecurityService {
    threat_detector: Arc<ThreatDetector>,
    response_engine: Arc<ResponseEngine>,
    request_limiter: Arc<RateLimiter>,
    metrics_recorder: Arc<MetricsRecorder>,
}

impl GuardianSecurityService {
    pub fn new(
        threat_detector: Arc<ThreatDetector>,
        response_engine: Arc<ResponseEngine>,
        config: SecurityServiceConfig,
    ) -> Self {
        info!(version = SERVICE_VERSION, "Initializing security service");

        Self {
            threat_detector,
            response_engine,
            request_limiter: Arc::new(RateLimiter::new(
                MAX_CONCURRENT_REQUESTS,
                RATE_LIMIT_WINDOW,
            )),
            metrics_recorder: Arc::new(MetricsRecorder::new("guardian.security")),
        }
    }
}

#[tonic::async_trait]
impl security_service_server::SecurityService for GuardianSecurityService {
    #[instrument(skip(self, request))]
    async fn detect_threats(
        &self,
        request: Request<()>,
    ) -> Result<Response<ThreatAlert>, Status> {
        let start_time = Instant::now();
        let method = "detect_threats";

        // Check rate limit
        self.request_limiter.check_rate_limit().await?;

        // Record request metrics
        self.metrics_recorder.record_request_count(method, "started");

        // Perform threat detection
        let result = self.threat_detector.analyze_threat()
            .await
            .map_err(|e| {
                error!(?e, "Threat detection failed");
                Status::internal(e.to_string())
            })?;

        // Convert result to response
        let response = ThreatAlert {
            alert_id: uuid::Uuid::new_v4().to_string(),
            severity: result.severity as i32,
            threat_type: result.threat_type as i32,
            confidence: result.confidence,
            timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
            details: result.details,
        };

        // Record metrics
        let duration = start_time.elapsed();
        self.metrics_recorder.record_request_latency(method, duration);
        self.metrics_recorder.record_request_count(method, "success");

        Ok(Response::new(response))
    }

    #[instrument(skip(self, request))]
    async fn detect_anomalies(
        &self,
        request: Request<()>,
    ) -> Result<Response<SecurityEvent>, Status> {
        let start_time = Instant::now();
        let method = "detect_anomalies";

        // Check rate limit
        self.request_limiter.check_rate_limit().await?;

        // Record request metrics
        self.metrics_recorder.record_request_count(method, "started");

        // Perform anomaly detection
        let result = self.threat_detector.detect_anomalies()
            .await
            .map_err(|e| {
                error!(?e, "Anomaly detection failed");
                Status::internal(e.to_string())
            })?;

        // Convert result to response
        let response = SecurityEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: result.event_type as i32,
            severity: result.severity as i32,
            timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
            details: result.details,
        };

        // Record metrics
        let duration = start_time.elapsed();
        self.metrics_recorder.record_request_latency(method, duration);
        self.metrics_recorder.record_request_count(method, "success");

        Ok(Response::new(response))
    }

    #[instrument(skip(self, request))]
    async fn execute_response(
        &self,
        request: Request<ThreatAlert>,
    ) -> Result<Response<SecurityResponse>, Status> {
        let start_time = Instant::now();
        let method = "execute_response";

        // Check rate limit
        self.request_limiter.check_rate_limit().await?;

        // Record request metrics
        self.metrics_recorder.record_request_count(method, "started");

        let alert = request.into_inner();

        // Validate request
        if alert.confidence < 0.0 || alert.confidence > 1.0 {
            return Err(Status::invalid_argument("Invalid confidence value"));
        }

        // Execute response
        let result = self.response_engine.execute_response(alert)
            .await
            .map_err(|e| {
                error!(?e, "Response execution failed");
                Status::internal(e.to_string())
            })?;

        // Convert result to response
        let response = SecurityResponse {
            response_id: result.response_id,
            alert_id: alert.alert_id,
            action_type: result.action_type as i32,
            status: result.status as i32,
            timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
        };

        // Record metrics
        let duration = start_time.elapsed();
        self.metrics_recorder.record_request_latency(method, duration);
        self.metrics_recorder.record_request_count(method, "success");

        Ok(Response::new(response))
    }
}

pub fn create_security_service(
    threat_detector: Arc<ThreatDetector>,
    response_engine: Arc<ResponseEngine>,
    config: SecurityServiceConfig,
) -> GuardianSecurityService {
    GuardianSecurityService::new(threat_detector, response_engine, config)
}