use std::{sync::Arc, time::Duration};
use parking_lot::RwLock;
use tonic::{Request, Response, Status};
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};
use metrics::{counter, gauge, histogram};

use crate::core::guardian::Guardian;
use crate::core::system_state::{SystemState, SystemHealth};
use crate::utils::error::GuardianError;

// Service constants
const SERVICE_NAME: &str = "guardian.v1.GuardianService";
const MAX_EVENT_STREAM_BUFFER: usize = 1000;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Circuit breaker for service reliability
#[derive(Debug)]
struct CircuitBreaker {
    failures: std::sync::atomic::AtomicU32,
    last_failure: parking_lot::RwLock<tokio::time::Instant>,
    is_open: std::sync::atomic::AtomicBool,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failures: std::sync::atomic::AtomicU32::new(0),
            last_failure: parking_lot::RwLock::new(tokio::time::Instant::now()),
            is_open: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self.last_failure.write() = tokio::time::Instant::now();
        
        if failures >= CIRCUIT_BREAKER_THRESHOLD {
            self.is_open.store(true, std::sync::atomic::Ordering::SeqCst);
            counter!("guardian.service.circuit_breaker.open", 1);
        }
    }

    fn is_open(&self) -> bool {
        self.is_open.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Enhanced gRPC service implementation for the Guardian system
#[derive(Debug)]
pub struct GuardianService {
    guardian: Arc<Guardian>,
    system_state: Arc<RwLock<SystemState>>,
    circuit_breaker: Arc<CircuitBreaker>,
    metrics_collector: Arc<crate::utils::metrics::MetricsCollector>,
}

impl GuardianService {
    /// Creates a new GuardianService instance with enhanced security and monitoring
    pub fn new(
        guardian: Arc<Guardian>,
        system_state: Arc<RwLock<SystemState>>,
    ) -> Result<Self, GuardianError> {
        let metrics_config = crate::utils::metrics::MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(MAX_EVENT_STREAM_BUFFER),
            flush_interval: Some(Duration::from_secs(10)),
            sampling_rates: None,
        };

        Ok(Self {
            guardian,
            system_state,
            circuit_breaker: Arc::new(CircuitBreaker::new()),
            metrics_collector: Arc::new(crate::utils::metrics::MetricsCollector::new(metrics_config)?),
        })
    }

    /// Validates request authentication and authorization
    #[instrument(skip(request))]
    fn validate_request<T>(&self, request: &Request<T>) -> Result<(), Status> {
        // Validate authentication token
        let token = request.metadata().get("authorization")
            .ok_or_else(|| Status::unauthenticated("Missing authentication token"))?;

        // Validate authorization
        if !self.check_authorization(token) {
            return Err(Status::permission_denied("Insufficient permissions"));
        }

        Ok(())
    }

    /// Checks request authorization
    fn check_authorization(&self, token: &tonic::metadata::MetadataValue<_>) -> bool {
        // TODO: Implement actual token validation
        true
    }
}

#[tonic::async_trait]
impl guardian_proto::guardian_service_server::GuardianService for GuardianService {
    /// Retrieves current system status with enhanced security and validation
    #[instrument(skip(self, request))]
    async fn get_system_status(
        &self,
        request: Request<guardian_proto::Empty>,
    ) -> Result<Response<guardian_proto::SystemStatus>, Status> {
        let start = tokio::time::Instant::now();
        
        // Validate request
        self.validate_request(&request)?;

        // Check circuit breaker
        if self.circuit_breaker.is_open() {
            return Err(Status::unavailable("Service circuit breaker is open"));
        }

        // Get system state with timeout
        let state = tokio::time::timeout(
            REQUEST_TIMEOUT,
            async {
                self.system_state.read().get_current_state()
            },
        )
        .await
        .map_err(|_| Status::deadline_exceeded("Request timeout"))??;

        // Convert to response
        let response = convert_system_status(state)?;

        // Record metrics
        histogram!("guardian.service.request_duration", start.elapsed().as_secs_f64());
        counter!("guardian.service.requests.success", 1);

        Ok(Response::new(response))
    }

    /// Streams system events with backpressure handling
    #[instrument(skip(self, request))]
    async fn monitor_events(
        &self,
        request: Request<guardian_proto::MonitorEventsRequest>,
    ) -> Result<Response<tonic::Streaming<guardian_proto::Event>>, Status> {
        self.validate_request(&request)?;

        let (tx, rx) = mpsc::channel(MAX_EVENT_STREAM_BUFFER);
        
        // Start event monitoring
        let guardian = Arc::clone(&self.guardian);
        tokio::spawn(async move {
            if let Err(e) = monitor_events(guardian, tx).await {
                error!(?e, "Error monitoring events");
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    /// Executes system response actions with validation
    #[instrument(skip(self, request))]
    async fn execute_response(
        &self,
        request: Request<guardian_proto::ExecuteResponseRequest>,
    ) -> Result<Response<guardian_proto::ExecuteResponseResponse>, Status> {
        self.validate_request(&request)?;

        let response = self.guardian.execute_action(request.into_inner().action)
            .await
            .map_err(|e| Status::internal(format!("Failed to execute response: {}", e)))?;

        Ok(Response::new(guardian_proto::ExecuteResponseResponse {
            success: true,
            message: "Response executed successfully".into(),
        }))
    }
}

/// Converts internal system status to gRPC response type
#[instrument(skip(state))]
fn convert_system_status(
    state: SystemState,
) -> Result<guardian_proto::SystemStatus, GuardianError> {
    Ok(guardian_proto::SystemStatus {
        health: match state.health {
            SystemHealth::Healthy => 0,
            SystemHealth::Degraded => 1,
            SystemHealth::Critical => 2,
        },
        cpu_usage: state.cpu_usage,
        memory_usage: state.memory_usage,
        active_threats: state.active_threats,
        last_update: state.last_update.timestamp(),
    })
}

/// Background task for monitoring system events
#[instrument(skip(guardian, tx))]
async fn monitor_events(
    guardian: Arc<Guardian>,
    tx: mpsc::Sender<guardian_proto::Event>,
) -> Result<(), GuardianError> {
    let mut event_stream = guardian.subscribe_events().await?;

    while let Some(event) = event_stream.recv().await {
        let proto_event = guardian_proto::Event {
            event_type: event.event_type,
            payload: serde_json::to_string(&event.payload)?,
            timestamp: event.timestamp.timestamp(),
            priority: event.priority as i32,
        };

        if tx.send(proto_event).await.is_err() {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_system_status() {
        let (guardian, system_state) = setup_test_environment().await;
        let service = GuardianService::new(guardian, system_state).unwrap();

        let request = Request::new(guardian_proto::Empty {});
        let response = service.get_system_status(request).await.unwrap();

        assert!(response.into_inner().cpu_usage >= 0.0);
    }

    async fn setup_test_environment() -> (Arc<Guardian>, Arc<RwLock<SystemState>>) {
        // Initialize test environment
        let config = crate::core::guardian::GuardianConfig::from_env().unwrap();
        let guardian = Arc::new(Guardian::new(config).await.unwrap());
        let system_state = Arc::new(RwLock::new(SystemState::new(
            crate::utils::metrics::MetricsCollector::new(
                crate::utils::metrics::MetricsConfig {
                    statsd_host: "localhost".into(),
                    statsd_port: 8125,
                    buffer_size: Some(1000),
                    flush_interval: Some(Duration::from_secs(10)),
                    sampling_rates: None,
                },
            ).unwrap(),
            crate::core::event_bus::EventBus::new(
                crate::core::metrics::CoreMetricsManager::new(
                    crate::utils::metrics::MetricsCollector::new(
                        crate::utils::metrics::MetricsConfig {
                            statsd_host: "localhost".into(),
                            statsd_port: 8125,
                            buffer_size: Some(1000),
                            flush_interval: Some(Duration::from_secs(10)),
                            sampling_rates: None,
                        },
                    ).unwrap(),
                    crate::core::metrics::MetricsConfig {
                        sampling_rates: std::collections::HashMap::new(),
                        priority_levels: std::collections::HashMap::new(),
                        buffer_size: 1000,
                    },
                ).unwrap(),
            ).unwrap(),
            crate::core::system_state::StateConfig {
                history_capacity: 1000,
                validation_timeout: Duration::from_millis(50),
                health_check_interval: Duration::from_secs(30),
            },
        ).unwrap()));

        (guardian, system_state)
    }
}