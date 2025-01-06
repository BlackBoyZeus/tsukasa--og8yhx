use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sysinfo::{System, SystemExt, CpuExt};
use tokio::runtime::Runtime;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

// Import internal components
use guardian::storage::{
    StorageManager,
    MetricsStore,
    EventStore,
};

// Constants for benchmark datasets
const BENCH_SMALL_DATASET: usize = 1_000;
const BENCH_MEDIUM_DATASET: usize = 10_000;
const BENCH_LARGE_DATASET: usize = 100_000;
const BENCH_BATCH_SIZES: [usize; 4] = [10, 100, 1000, 10000];
const BENCH_QUERY_RANGES: [i64; 3] = [1, 7, 30]; // Days
const BENCH_CONCURRENT_OPS: usize = 4;

/// Benchmarks metrics storage operations with varied workloads
fn bench_metrics_store(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("metrics_store");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(30));

    // Initialize system monitoring
    let mut sys = System::new_all();

    // Setup metrics store
    let storage_manager = rt.block_on(async {
        StorageManager::new(Default::default()).unwrap()
    });
    let metrics_store = rt.block_on(async {
        MetricsStore::new(
            storage_manager.zfs_manager.clone(),
            90, // retention days
            1000, // batch size
            6, // compression level
        ).await.unwrap()
    });

    // Benchmark single metric storage
    group.bench_function("store_single_metric", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            rt.block_on(async {
                for _ in 0..iters {
                    let metric = create_test_metric();
                    black_box(metrics_store.store_metrics(vec![metric]).await.unwrap());
                }
            });
            start.elapsed()
        });
    });

    // Benchmark batch operations with different sizes
    for &batch_size in &BENCH_BATCH_SIZES {
        group.bench_with_input(
            BenchmarkId::new("store_batch_metrics", batch_size),
            &batch_size,
            |b, &size| {
                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    rt.block_on(async {
                        for _ in 0..iters {
                            let metrics = create_test_metrics(size);
                            black_box(metrics_store.store_metrics(metrics).await.unwrap());
                        }
                    });
                    start.elapsed()
                });
            },
        );
    }

    // Benchmark queries with different time ranges
    for &days in &BENCH_QUERY_RANGES {
        group.bench_with_input(
            BenchmarkId::new("query_metrics", days),
            &days,
            |b, &days| {
                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    rt.block_on(async {
                        for _ in 0..iters {
                            let query = create_test_query(days);
                            black_box(metrics_store.query_metrics(query).await.unwrap());
                        }
                    });
                    start.elapsed()
                });
            },
        );
    }

    // Benchmark concurrent operations
    group.bench_function("concurrent_operations", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            rt.block_on(async {
                for _ in 0..iters {
                    let mut handles = Vec::new();
                    for _ in 0..BENCH_CONCURRENT_OPS {
                        let metrics_store = metrics_store.clone();
                        handles.push(tokio::spawn(async move {
                            let metrics = create_test_metrics(100);
                            black_box(metrics_store.store_metrics(metrics).await.unwrap());
                        }));
                    }
                    for handle in handles {
                        black_box(handle.await.unwrap());
                    }
                }
            });
            start.elapsed()
        });
    });

    // Record system resource utilization
    sys.refresh_all();
    let cpu_usage = sys.global_cpu_info().cpu_usage();
    let memory_used = sys.used_memory();
    
    group.finish();
}

/// Benchmarks event storage operations with realistic scenarios
fn bench_event_store(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("event_store");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(30));

    // Setup event store
    let storage_manager = rt.block_on(async {
        StorageManager::new(Default::default()).unwrap()
    });
    let event_store = rt.block_on(async {
        EventStore::new(
            storage_manager.zfs_manager.clone(),
            "events".to_string(),
        ).await.unwrap()
    });

    // Benchmark single event storage
    group.bench_function("store_single_event", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            rt.block_on(async {
                for _ in 0..iters {
                    let event = create_test_event();
                    black_box(event_store.store_event(event).await.unwrap());
                }
            });
            start.elapsed()
        });
    });

    // Benchmark event queries across time ranges
    for &days in &BENCH_QUERY_RANGES {
        group.bench_with_input(
            BenchmarkId::new("query_events", days),
            &days,
            |b, &days| {
                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    rt.block_on(async {
                        for _ in 0..iters {
                            let (start_time, end_time) = create_time_range(days);
                            black_box(
                                event_store
                                    .query_events(start_time, end_time, None)
                                    .await
                                    .unwrap()
                            );
                        }
                    });
                    start.elapsed()
                });
            },
        );
    }

    group.finish();
}

/// Benchmarks partition-related operations
fn bench_partition_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("partition_operations");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(30));

    // Setup storage components
    let storage_manager = rt.block_on(async {
        StorageManager::new(Default::default()).unwrap()
    });

    // Benchmark partition creation
    group.bench_function("create_partition", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            rt.block_on(async {
                for i in 0..iters {
                    let partition_name = format!("bench_partition_{}", i);
                    black_box(
                        storage_manager
                            .zfs_manager
                            .create_dataset(
                                &partition_name,
                                Some(HashMap::from([
                                    ("compression".to_string(), "lz4".to_string()),
                                ])),
                                None,
                            )
                            .await
                            .unwrap()
                    );
                }
            });
            start.elapsed()
        });
    });

    group.finish();
}

// Helper functions for creating test data
fn create_test_metric() -> MetricsStore::Metric {
    MetricsStore::Metric {
        name: "test_metric".to_string(),
        value: rand::random::<f64>(),
        timestamp: Utc::now(),
        metric_type: MetricType::Counter,
        tags: HashMap::new(),
    }
}

fn create_test_metrics(count: usize) -> Vec<MetricsStore::Metric> {
    (0..count).map(|_| create_test_metric()).collect()
}

fn create_test_query(days: i64) -> MetricsQuery {
    let end_time = Utc::now();
    let start_time = end_time - Duration::days(days);
    MetricsQuery {
        time_range: (start_time, end_time),
        metric_names: None,
    }
}

fn create_test_event() -> Event {
    Event::new(
        "test_event".to_string(),
        serde_json::json!({"test": "data"}),
        EventPriority::High,
    ).unwrap()
}

fn create_time_range(days: i64) -> (DateTime<Utc>, DateTime<Utc>) {
    let end_time = Utc::now();
    let start_time = end_time - Duration::days(days);
    (start_time, end_time)
}

criterion_group!(
    storage_benches,
    bench_metrics_store,
    bench_event_store,
    bench_partition_operations
);
criterion_main!(storage_benches);