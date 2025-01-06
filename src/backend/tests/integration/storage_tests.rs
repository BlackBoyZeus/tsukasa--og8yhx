use assert_matches::assert_matches;
use chrono::{DateTime, Duration, Utc};
use tokio;

use crate::storage::{
    StorageManager,
    StorageHealth,
    StorageStats,
    OptimizationConfig,
    StorageIOPriority,
};
use crate::storage::metrics_store::{MetricsStore, Metric, MetricsQuery};
use crate::storage::event_store::{EventStore, Event};
use crate::utils::error::GuardianError;

// Test constants
const TEST_ZFS_POOL: &str = "guardian_test";
const TEST_RETENTION_DAYS: u32 = 90;
const TEST_METRICS_COUNT: usize = 1000;
const TEST_EVENTS_COUNT: usize = 1000;
const TEST_COMPRESSION_LEVEL: u32 = 6;

/// Sets up a clean test storage environment
async fn setup_test_storage() -> Result<StorageManager, GuardianError> {
    // Create test storage configuration
    let config = StorageConfig {
        zfs_pool_name: TEST_ZFS_POOL.to_string(),
        encryption_enabled: true,
        compression_algorithm: "lz4".to_string(),
        compression_level: TEST_COMPRESSION_LEVEL,
        io_priority: StorageIOPriority::Normal,
        retention_policy: RetentionPolicy {
            system_events_days: TEST_RETENTION_DAYS,
            security_alerts_days: TEST_RETENTION_DAYS * 2,
            ml_model_versions: 5,
            audit_logs_days: TEST_RETENTION_DAYS * 4,
        },
        quota_settings: QuotaSettings {
            max_pool_size_gb: 10,
            alert_threshold_percent: 85,
            reserve_space_percent: 10,
        },
        backup_enabled: false,
        snapshot_schedule: SnapshotConfig {
            enabled: true,
            interval_hours: 24,
            retention_count: 7,
            auto_cleanup: true,
        },
    };

    let manager = StorageManager::new(config)?;
    manager.init().await?;
    Ok(manager)
}

#[tokio::test]
async fn test_storage_initialization() -> Result<(), GuardianError> {
    let manager = setup_test_storage().await?;
    
    // Verify initial storage health
    let health = manager.get_health_status().await?;
    assert_eq!(health, StorageHealth::Healthy);

    // Verify initial storage stats
    let stats = manager.get_storage_stats().await?;
    assert!(stats.compression_ratio >= 1.0);
    assert!(stats.used_space < stats.total_space);

    Ok(())
}

#[tokio::test]
async fn test_metrics_storage() -> Result<(), GuardianError> {
    let manager = setup_test_storage().await?;
    let metrics_store = manager.metrics_store.clone();

    // Generate test metrics
    let start_time = Utc::now();
    let mut test_metrics = Vec::with_capacity(TEST_METRICS_COUNT);
    for i in 0..TEST_METRICS_COUNT {
        test_metrics.push(Metric {
            name: format!("test_metric_{}", i),
            value: i as f64,
            timestamp: start_time + Duration::seconds(i as i64),
            metric_type: MetricType::Counter,
            tags: HashMap::new(),
        });
    }

    // Store metrics in batches
    for chunk in test_metrics.chunks(100) {
        metrics_store.store_metrics(chunk.to_vec()).await?;
    }

    // Query metrics with time range
    let query = MetricsQuery {
        time_range: (start_time, start_time + Duration::hours(1)),
        metric_names: None,
    };
    let retrieved_metrics = metrics_store.query_metrics(query).await?;

    // Verify metrics retention and retrieval
    assert!(!retrieved_metrics.is_empty());
    assert!(retrieved_metrics.len() <= TEST_METRICS_COUNT);
    
    // Verify compression and resource usage
    let stats = manager.get_storage_stats().await?;
    assert!(stats.compression_ratio >= 1.2);
    assert!(stats.used_space < stats.total_space * 90 / 100); // Less than 90% usage

    Ok(())
}

#[tokio::test]
async fn test_event_storage() -> Result<(), GuardianError> {
    let manager = setup_test_storage().await?;
    let event_store = manager.event_store.clone();

    // Generate test events
    let start_time = Utc::now();
    let mut test_events = Vec::with_capacity(TEST_EVENTS_COUNT);
    for i in 0..TEST_EVENTS_COUNT {
        test_events.push(Event::new(
            format!("test_event_{}", i),
            serde_json::json!({ "value": i }),
            EventPriority::High,
        )?);
    }

    // Store events with partitioning
    for event in test_events {
        event_store.store_event(event).await?;
    }

    // Query events with time range
    let retrieved_events = event_store.query_events(
        start_time,
        start_time + Duration::hours(1),
        None,
    ).await?;

    // Verify event retention and retrieval
    assert!(!retrieved_events.is_empty());
    assert!(retrieved_events.len() <= TEST_EVENTS_COUNT);

    // Test event partitioning
    let partitions = event_store.get_partitions_in_range(
        start_time,
        start_time + Duration::hours(1),
    ).await?;
    assert!(!partitions.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_storage_performance() -> Result<(), GuardianError> {
    let manager = setup_test_storage().await?;
    
    // Configure optimization settings
    let optimization = OptimizationConfig {
        compression_level: TEST_COMPRESSION_LEVEL,
        io_priority: StorageIOPriority::High,
        cache_size_mb: 512,
        prefetch_enabled: true,
    };

    // Apply optimization
    manager.optimize_storage(optimization).await?;

    // Measure write performance
    let start_time = Utc::now();
    let mut write_latencies = Vec::new();

    for i in 0..100 {
        let write_start = Utc::now();
        
        // Perform concurrent writes
        let metrics_future = manager.metrics_store.store_metrics(vec![Metric {
            name: format!("perf_metric_{}", i),
            value: i as f64,
            timestamp: start_time,
            metric_type: MetricType::Counter,
            tags: HashMap::new(),
        }]);

        let event_future = manager.event_store.store_event(Event::new(
            format!("perf_event_{}", i),
            serde_json::json!({ "value": i }),
            EventPriority::High,
        )?);

        tokio::try_join!(metrics_future, event_future)?;

        write_latencies.push(Utc::now().signed_duration_since(write_start).num_milliseconds());
    }

    // Verify performance metrics
    let avg_write_latency = write_latencies.iter().sum::<i64>() as f64 / write_latencies.len() as f64;
    assert!(avg_write_latency < 100.0); // Less than 100ms average write latency

    // Verify resource utilization
    let stats = manager.get_storage_stats().await?;
    assert!(stats.compression_ratio >= 1.2);
    assert!(stats.io_operations > 0);
    assert!(stats.cache_hits > 0);

    Ok(())
}

#[tokio::test]
async fn test_storage_cleanup() -> Result<(), GuardianError> {
    let manager = setup_test_storage().await?;
    
    // Create old test data
    let old_time = Utc::now() - Duration::days(TEST_RETENTION_DAYS as i64 + 1);
    
    // Store old metrics
    manager.metrics_store.store_metrics(vec![Metric {
        name: "old_metric".to_string(),
        value: 1.0,
        timestamp: old_time,
        metric_type: MetricType::Counter,
        tags: HashMap::new(),
    }]).await?;

    // Store old event
    manager.event_store.store_event(Event::new(
        "old_event".to_string(),
        serde_json::json!({ "value": 1 }),
        EventPriority::Low,
    )?).await?;

    // Trigger cleanup
    manager.metrics_store.cleanup_expired_metrics().await?;
    manager.event_store.cleanup_expired_events().await?;

    // Verify old data is removed
    let query = MetricsQuery {
        time_range: (old_time, old_time + Duration::hours(1)),
        metric_names: None,
    };
    let old_metrics = manager.metrics_store.query_metrics(query).await?;
    assert!(old_metrics.is_empty());

    let old_events = manager.event_store.query_events(
        old_time,
        old_time + Duration::hours(1),
        None,
    ).await?;
    assert!(old_events.is_empty());

    Ok(())
}