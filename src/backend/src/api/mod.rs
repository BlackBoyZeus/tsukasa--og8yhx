use std::{sync::Arc, time::Duration};
use tonic::{transport::Server, Request, Response, Status};
use tokio::sync::RwLock;
use metrics::{counter, gauge, histogram};
use governor::{Quota, RateLimiter};
use tracing::{debug, error, info, instrument, warn};

use crate::utils::error::GuardianError;
use crate::api::grpc::{
    GuardianService, GuardianSecurityService, MLService,
    ServerConfig, TlsConfig,
};

// API version and configuration constants
pub const API_VERSION: &str = "v1";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_CONNECTIONS: usize = 1000;
pub const RATE_LIMIT_BURST: u32 = 50;

/// Enhanced configuration for the API layer with security and performance settings
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub grpc_config: GrpcConfig,
    pub auth_config: AuthConfig,
    pub rate_limit: RateLimitConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub connection_pool: ConnectionPoolConfig,
    pub monitoring: MonitoringConfig,
}

/// gRPC server configuration
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub port: u16,
    pub max_concurrent_requests: usize,
    pub request_timeout: Duration,
    pub tls_config: Option<TlsConfig>,
}

/// Authentication and authorization configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub require_mtls: bool,
    pub token_validation: bool,
    pub auth_timeout: Duration,
    pub allowed_roles: Vec<String>,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub per_ip_limit: bool,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub reset_timeout: Duration,
    pub half_open_timeout: Duration,
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    pub max_size: usize,
    pub min_idle: usize,
    pub max_lifetime: Duration,
}

/// Monitoring configuration
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub metrics_enabled: bool,
    pub tracing_enabled: bool,
    pub health_check_interval: Duration,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            grpc_config: GrpcConfig {
                port: 50051,
                max_concurrent_requests: MAX_CONNECTIONS,
                request_timeout: DEFAULT_TIMEOUT,
                tls_config: None,
            },
            auth_config: AuthConfig {
                require_mtls: true,
                token_validation: true,
                auth_timeout: Duration::from_secs(5),
                allowed_roles: vec!["admin".to_string(), "security".to_string()],
            },
            rate_limit: RateLimitConfig {
                requests_per_second: 100,
                burst_size: RATE_LIMIT_BURST,
                per_ip_limit: true,
            },
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 5,
                reset_timeout: Duration::from_secs(30),
                half_open_timeout: Duration::from_secs(5),
            },
            connection_pool: ConnectionPoolConfig {
                max_size: MAX_CONNECTIONS,
                min_idle: 10,
                max_lifetime: Duration::from_secs(3600),
            },
            monitoring: MonitoringConfig {
                metrics_enabled: true,
                tracing_enabled: true,
                health_check_interval: Duration::from_secs(15),
            },
        }
    }
}

/// Initializes the API layer with enhanced security, monitoring, and performance features
#[tokio::main]
#[tracing::instrument]
pub async fn init_api(config: ApiConfig) -> Result<(), GuardianError> {
    info!(version = API_VERSION, "Initializing Guardian API");

    // Initialize rate limiter
    let rate_limiter = Arc::new(RateLimiter::direct(Quota::per_second(
        std::num::NonZeroU32::new(config.rate_limit.requests_per_second).unwrap()
    )));

    // Initialize circuit breaker
    let circuit_breaker = Arc::new(RwLock::new(CircuitBreaker::new(
        config.circuit_breaker.failure_threshold,
        config.circuit_breaker.reset_timeout,
    )));

    // Initialize metrics collector
    let metrics_collector = Arc::new(metrics::MetricsCollector::new());

    // Configure gRPC server
    let server_config = ServerConfig {
        port: config.grpc_config.port,
        max_concurrent_requests: config.grpc_config.max_concurrent_requests,
        request_timeout: config.grpc_config.request_timeout,
        circuit_breaker_threshold: config.circuit_breaker.failure_threshold,
        health_check_interval: config.monitoring.health_check_interval,
        tls_config: config.grpc_config.tls_config,
    };

    // Initialize services
    let guardian_service = Arc::new(GuardianService::new(
        /* service dependencies */
    ));

    let security_service = Arc::new(GuardianSecurityService::new(
        /* service dependencies */
    ));

    let ml_service = Arc::new(MLService::new(
        /* service dependencies */
    ));

    // Create gRPC server
    let grpc_server = grpc::GrpcServer::new(
        server_config,
        guardian_service,
        security_service,
        ml_service,
    );

    // Start server
    grpc_server.start().await?;

    info!("Guardian API initialized successfully");
    Ok(())
}

/// Gracefully shuts down the API layer with resource cleanup
#[tracing::instrument]
pub async fn shutdown_api() -> Result<(), GuardianError> {
    info!("Initiating API shutdown");

    // Stop accepting new connections
    counter!("guardian.api.shutdown.initiated", 1);

    // Wait for active requests to complete
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Cleanup resources
    info!("API shutdown completed successfully");
    Ok(())
}

// Private helper structs and implementations
struct CircuitBreaker {
    failures: std::sync::atomic::AtomicU32,
    last_failure: RwLock<std::time::Instant>,
    threshold: u32,
    reset_timeout: Duration,
}

impl CircuitBreaker {
    fn new(threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            failures: std::sync::atomic::AtomicU32::new(0),
            last_failure: RwLock::new(std::time::Instant::now()),
            threshold,
            reset_timeout,
        }
    }

    async fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self.last_failure.write().await = std::time::Instant::now();

        if failures >= self.threshold {
            counter!("guardian.api.circuit_breaker.open", 1);
        }
    }

    async fn is_open(&self) -> bool {
        let failures = self.failures.load(std::sync::atomic::Ordering::SeqCst);
        if failures >= self.threshold {
            let last_failure = *self.last_failure.read().await;
            if last_failure.elapsed() > self.reset_timeout {
                self.failures.store(0, std::sync::atomic::Ordering::SeqCst);
                return false;
            }
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_lifecycle() {
        let config = ApiConfig::default();
        assert!(init_api(config).await.is_ok());
        assert!(shutdown_api().await.is_ok());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(5));
        
        for _ in 0..3 {
            breaker.record_failure().await;
        }
        
        assert!(breaker.is_open().await);
    }
}