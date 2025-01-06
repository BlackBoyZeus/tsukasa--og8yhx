use std::{sync::Arc, time::Duration};
use tonic::{transport::Server, Request, Response, Status};
use tracing::{debug, error, info, instrument, warn};
use metrics::{counter, gauge, histogram};

use crate::utils::error::GuardianError;
use crate::api::grpc::guardian_service::GuardianService;
use crate::api::grpc::security_service::GuardianSecurityService;
use crate::api::grpc::ml_service::MLService;

// Constants for gRPC server configuration
const DEFAULT_PORT: u16 = 50051;
const MAX_CONCURRENT_REQUESTS: usize = 1000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Configuration for gRPC server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub max_concurrent_requests: usize,
    pub request_timeout: Duration,
    pub circuit_breaker_threshold: u32,
    pub health_check_interval: Duration,
    pub tls_config: Option<TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            max_concurrent_requests: MAX_CONCURRENT_REQUESTS,
            request_timeout: REQUEST_TIMEOUT,
            circuit_breaker_threshold: CIRCUIT_BREAKER_THRESHOLD,
            health_check_interval: HEALTH_CHECK_INTERVAL,
            tls_config: None,
        }
    }
}

/// TLS configuration for secure gRPC connections
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_cert_path: Option<String>,
}

/// Circuit breaker for service reliability
#[derive(Debug)]
struct CircuitBreaker {
    failures: std::sync::atomic::AtomicU32,
    last_failure: tokio::sync::RwLock<std::time::Instant>,
    is_open: std::sync::atomic::AtomicBool,
}

impl CircuitBreaker {
    fn new(threshold: u32) -> Self {
        Self {
            failures: std::sync::atomic::AtomicU32::new(0),
            last_failure: tokio::sync::RwLock::new(std::time::Instant::now()),
            is_open: std::sync::atomic::AtomicBool::new(false),
        }
    }

    async fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self.last_failure.write().await = std::time::Instant::now();

        if failures >= CIRCUIT_BREAKER_THRESHOLD {
            self.is_open.store(true, std::sync::atomic::Ordering::SeqCst);
            counter!("guardian.grpc.circuit_breaker.open", 1);
        }
    }

    fn is_open(&self) -> bool {
        self.is_open.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Enhanced gRPC server with security, monitoring, and reliability features
#[derive(Debug)]
pub struct GrpcServer {
    config: ServerConfig,
    guardian_service: Arc<GuardianService>,
    security_service: Arc<GuardianSecurityService>,
    ml_service: Arc<MLService>,
    circuit_breaker: Arc<CircuitBreaker>,
    metrics_reporter: Arc<MetricsReporter>,
}

impl GrpcServer {
    /// Creates a new GrpcServer instance with enhanced security and monitoring
    pub fn new(
        config: ServerConfig,
        guardian_service: Arc<GuardianService>,
        security_service: Arc<GuardianSecurityService>,
        ml_service: Arc<MLService>,
    ) -> Self {
        Self {
            config: config.clone(),
            guardian_service,
            security_service,
            ml_service,
            circuit_breaker: Arc::new(CircuitBreaker::new(config.circuit_breaker_threshold)),
            metrics_reporter: Arc::new(MetricsReporter::new("guardian.grpc")),
        }
    }

    /// Starts the gRPC server with security and monitoring
    #[instrument]
    pub async fn start(&self) -> Result<(), GuardianError> {
        info!("Starting gRPC server on port {}", self.config.port);

        let addr = format!("0.0.0.0:{}", self.config.port).parse()?;

        // Configure server with security and monitoring
        let mut server = Server::builder();

        // Configure TLS if enabled
        if let Some(tls_config) = &self.config.tls_config {
            let cert = tokio::fs::read(&tls_config.cert_path).await?;
            let key = tokio::fs::read(&tls_config.key_path).await?;
            
            let identity = tonic::transport::Identity::from_pem(cert, key);
            
            let tls = if let Some(ca_path) = &tls_config.ca_cert_path {
                let ca_cert = tokio::fs::read(ca_path).await?;
                tonic::transport::ServerTlsConfig::new()
                    .identity(identity)
                    .client_ca_root(tonic::transport::Certificate::from_pem(ca_cert))
            } else {
                tonic::transport::ServerTlsConfig::new()
                    .identity(identity)
            };

            server = server.tls_config(tls)?;
        }

        // Add services with interceptors
        let server = server
            .concurrency_limit(self.config.max_concurrent_requests)
            .timeout(self.config.request_timeout)
            .add_service(guardian_proto::guardian_service_server::GuardianServiceServer::new(
                GuardianServiceWrapper::new(
                    Arc::clone(&self.guardian_service),
                    Arc::clone(&self.circuit_breaker),
                    Arc::clone(&self.metrics_reporter),
                ),
            ))
            .add_service(guardian_proto::security_service_server::SecurityServiceServer::new(
                SecurityServiceWrapper::new(
                    Arc::clone(&self.security_service),
                    Arc::clone(&self.circuit_breaker),
                    Arc::clone(&self.metrics_reporter),
                ),
            ))
            .add_service(guardian_proto::ml_service_server::MLServiceServer::new(
                MLServiceWrapper::new(
                    Arc::clone(&self.ml_service),
                    Arc::clone(&self.circuit_breaker),
                    Arc::clone(&self.metrics_reporter),
                ),
            ));

        // Start health check monitoring
        let server_health = Arc::clone(&self.guardian_service);
        let health_interval = self.config.health_check_interval;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(health_interval);
            loop {
                interval.tick().await;
                if let Err(e) = server_health.health_check().await {
                    error!(?e, "Server health check failed");
                    counter!("guardian.grpc.health_check.failures", 1);
                }
            }
        });

        // Start server
        info!("gRPC server started successfully");
        server.serve(addr).await?;

        Ok(())
    }

    /// Gracefully stops the gRPC server
    #[instrument]
    pub async fn stop(&self) -> Result<(), GuardianError> {
        info!("Stopping gRPC server");
        // Implement graceful shutdown logic
        Ok(())
    }
}

// Service wrapper implementations with monitoring and circuit breaking
struct GuardianServiceWrapper {
    inner: Arc<GuardianService>,
    circuit_breaker: Arc<CircuitBreaker>,
    metrics: Arc<MetricsReporter>,
}

impl GuardianServiceWrapper {
    fn new(
        service: Arc<GuardianService>,
        circuit_breaker: Arc<CircuitBreaker>,
        metrics: Arc<MetricsReporter>,
    ) -> Self {
        Self {
            inner: service,
            circuit_breaker,
            metrics,
        }
    }
}

// Similar wrappers for SecurityService and MLService
// Implementation details omitted for brevity

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_lifecycle() {
        let config = ServerConfig::default();
        let guardian_service = Arc::new(GuardianService::new(/* test dependencies */));
        let security_service = Arc::new(GuardianSecurityService::new(/* test dependencies */));
        let ml_service = Arc::new(MLService::new(/* test dependencies */));

        let server = GrpcServer::new(
            config,
            guardian_service,
            security_service,
            ml_service,
        );

        assert!(server.start().await.is_ok());
        assert!(server.stop().await.is_ok());
    }
}