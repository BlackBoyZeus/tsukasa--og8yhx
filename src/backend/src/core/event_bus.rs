use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{broadcast, mpsc},
    time,
};
use tracing::{debug, error, info, instrument, warn};

use crate::utils::error::{GuardianError, SystemError, ValidationError};
use crate::core::metrics::CoreMetricsManager;

// Constants for event bus configuration
const MAX_SUBSCRIBERS: usize = 1000;
const CHANNEL_BUFFER_SIZE: usize = 1024;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const PUBLISH_TIMEOUT: Duration = Duration::from_millis(100);
const HIGH_PRIORITY_BUFFER: usize = 2048;

/// Event priority levels for processing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Core event structure with enhanced metadata
#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: String,
    pub payload: serde_json::Value,
    pub timestamp: time::OffsetDateTime,
    pub priority: EventPriority,
    pub correlation_id: uuid::Uuid,
    pub metadata: HashMap<String, String>,
}

impl Event {
    /// Creates a new event with validation
    pub fn new(
        event_type: String,
        payload: serde_json::Value,
        priority: EventPriority,
    ) -> Result<Self, GuardianError> {
        if event_type.is_empty() {
            return Err(ValidationError {
                context: "Event type cannot be empty".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        Ok(Self {
            event_type,
            payload,
            timestamp: time::OffsetDateTime::now_utc(),
            priority,
            correlation_id: uuid::Uuid::new_v4(),
            metadata: HashMap::new(),
        })
    }
}

/// High-performance event bus with priority handling and backpressure management
#[derive(Debug)]
pub struct EventBus {
    subscribers: RwLock<HashMap<String, Vec<mpsc::Sender<Event>>>>,
    metrics: CoreMetricsManager,
    shutdown_signal: broadcast::Sender<()>,
    circuit_breaker: Arc<AtomicBool>,
}

impl EventBus {
    /// Creates a new EventBus instance with monitoring
    pub fn new(metrics: CoreMetricsManager) -> Result<Self, GuardianError> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let bus = Self {
            subscribers: RwLock::new(HashMap::new()),
            metrics,
            shutdown_signal: shutdown_tx,
            circuit_breaker: Arc::new(AtomicBool::new(false)),
        };

        // Start background cleanup task
        let bus_clone = bus.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                if let Err(e) = cleanup_disconnected_subscribers(&bus_clone.subscribers) {
                    error!(?e, "Failed to cleanup disconnected subscribers");
                }
            }
        });

        Ok(bus)
    }

    /// Publishes an event with priority handling and backpressure management
    #[instrument(skip(self, event))]
    pub async fn publish(&self, event: Event) -> Result<(), GuardianError> {
        if self.circuit_breaker.load(Ordering::Relaxed) {
            return Err(SystemError {
                context: "Circuit breaker is open".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            });
        }

        let start_time = time::Instant::now();
        let subscribers = self.subscribers.read();
        
        if let Some(subs) = subscribers.get(&event.event_type) {
            let mut failed_deliveries = 0;
            
            for subscriber in subs {
                let timeout = match event.priority {
                    EventPriority::Critical => PUBLISH_TIMEOUT * 2,
                    EventPriority::High => PUBLISH_TIMEOUT,
                    _ => PUBLISH_TIMEOUT / 2,
                };

                match time::timeout(timeout, subscriber.send(event.clone())).await {
                    Ok(Ok(_)) => {
                        self.metrics.record_event_latency(
                            "event_delivery",
                            start_time.elapsed().as_secs_f64(),
                        ).await?;
                    }
                    Ok(Err(_)) | Err(_) => {
                        failed_deliveries += 1;
                        warn!(
                            event_type = %event.event_type,
                            "Failed to deliver event to subscriber"
                        );
                    }
                }
            }

            if failed_deliveries > 0 {
                self.metrics.record_system_metric(
                    "failed_deliveries".into(),
                    failed_deliveries as f64,
                    None,
                ).await?;
            }
        }

        Ok(())
    }

    /// Subscribes to events with backpressure control
    pub async fn subscribe(
        &self,
        event_type: String,
    ) -> Result<mpsc::Receiver<Event>, GuardianError> {
        let mut subscribers = self.subscribers.write();
        
        let buffer_size = match event_type.as_str() {
            "critical" => HIGH_PRIORITY_BUFFER,
            _ => CHANNEL_BUFFER_SIZE,
        };

        let (tx, rx) = mpsc::channel(buffer_size);
        
        subscribers
            .entry(event_type.clone())
            .or_insert_with(Vec::new)
            .push(tx);

        if subscribers.values().flatten().count() > MAX_SUBSCRIBERS {
            return Err(SystemError {
                context: "Maximum subscriber limit reached".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            });
        }

        debug!(event_type = %event_type, "New subscriber registered");
        Ok(rx)
    }

    /// Initiates graceful shutdown of the event bus
    pub async fn shutdown(&self) -> Result<(), GuardianError> {
        info!("Initiating event bus shutdown");
        let _ = self.shutdown_signal.send(());
        
        // Allow time for cleanup
        time::sleep(Duration::from_secs(1)).await;
        Ok(())
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            subscribers: RwLock::new(self.subscribers.read().clone()),
            metrics: self.metrics.clone(),
            shutdown_signal: self.shutdown_signal.clone(),
            circuit_breaker: Arc::clone(&self.circuit_breaker),
        }
    }
}

/// Removes disconnected subscribers with metrics tracking
#[instrument]
async fn cleanup_disconnected_subscribers(
    subscribers: &RwLock<HashMap<String, Vec<mpsc::Sender<Event>>>>
) -> Result<(), GuardianError> {
    let mut write_guard = subscribers.write();
    let mut total_removed = 0;

    for subscribers_list in write_guard.values_mut() {
        let initial_count = subscribers_list.len();
        subscribers_list.retain(|subscriber| !subscriber.is_closed());
        total_removed += initial_count - subscribers_list.len();
    }

    // Remove empty event types
    write_guard.retain(|_, subscribers| !subscribers.is_empty());

    if total_removed > 0 {
        debug!(removed = total_removed, "Cleaned up disconnected subscribers");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::metrics::CoreMetricsManager;
    use crate::utils::metrics::MetricsCollector;

    #[tokio::test]
    async fn test_event_publishing() {
        let metrics = setup_test_metrics();
        let bus = EventBus::new(metrics).unwrap();

        let event = Event::new(
            "test_event".into(),
            serde_json::json!({"test": "data"}),
            EventPriority::High,
        ).unwrap();

        let _rx = bus.subscribe("test_event".into()).await.unwrap();
        assert!(bus.publish(event).await.is_ok());
    }

    #[tokio::test]
    async fn test_subscriber_cleanup() {
        let metrics = setup_test_metrics();
        let bus = EventBus::new(metrics).unwrap();

        let rx = bus.subscribe("test_event".into()).await.unwrap();
        drop(rx); // Force disconnect

        time::sleep(Duration::from_secs(2)).await;
        let subscribers = bus.subscribers.read();
        assert!(subscribers.get("test_event").unwrap().is_empty());
    }

    fn setup_test_metrics() -> CoreMetricsManager {
        let collector_config = crate::utils::metrics::MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(100),
            flush_interval: Some(Duration::from_secs(1)),
            sampling_rates: None,
        };

        let collector = MetricsCollector::new(collector_config).unwrap();
        CoreMetricsManager::new(
            collector,
            crate::core::metrics::MetricsConfig {
                sampling_rates: HashMap::new(),
                priority_levels: HashMap::new(),
                buffer_size: 1000,
            },
        ).unwrap()
    }
}