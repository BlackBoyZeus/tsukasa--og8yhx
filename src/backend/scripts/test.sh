#!/bin/bash
set -euo pipefail

# Global configuration
TEST_DIR="$(pwd)/target/test"
BENCH_DIR="$(pwd)/target/criterion"
LOG_LEVEL="debug"
PARALLEL_JOBS="$(nproc)"
GPU_ENABLED="$(check_gpu_availability)"
METRICS_DIR="$(pwd)/target/metrics"
RESOURCE_LIMITS="cpu=400,memory=4G"

# Function to check GPU availability
check_gpu_availability() {
    if command -v nvidia-smi &> /dev/null; then
        echo "true"
    else
        echo "false"
    fi
}

# Setup test environment
setup_test_env() {
    echo "Setting up test environment..."
    
    # Create test directories
    mkdir -p "${TEST_DIR}"
    mkdir -p "${BENCH_DIR}"
    mkdir -p "${METRICS_DIR}"

    # Set environment variables
    export RUST_LOG="${LOG_LEVEL}"
    export RUST_BACKTRACE=1
    export GUARDIAN_TEST_DIR="${TEST_DIR}"
    export GUARDIAN_METRICS_DIR="${METRICS_DIR}"
    export GUARDIAN_RESOURCE_LIMITS="${RESOURCE_LIMITS}"

    # Initialize resource monitoring
    if ! command -v vmstat &> /dev/null; then
        echo "Error: vmstat not found. Please install sysstat package."
        exit 1
    fi

    # Start resource monitoring
    vmstat 1 > "${METRICS_DIR}/resource_usage.log" &
    MONITOR_PID=$!
    trap "kill ${MONITOR_PID}" EXIT

    # Configure GPU if available
    if [ "${GPU_ENABLED}" = "true" ]; then
        echo "Configuring GPU for testing..."
        nvidia-smi -pm 1
        nvidia-smi -lgc 1500
    fi

    echo "Test environment setup complete"
}

# Run unit tests
run_unit_tests() {
    echo "Running unit tests..."
    
    # Start resource monitoring
    local start_time=$(date +%s)
    
    # Run tests in parallel with resource monitoring
    RUST_TEST_THREADS="${PARALLEL_JOBS}" cargo test \
        --all \
        --lib \
        --bins \
        -- \
        --test-threads="${PARALLEL_JOBS}" \
        --nocapture \
        2>&1 | tee "${METRICS_DIR}/unit_tests.log"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Validate resource usage
    check_resource_usage "${METRICS_DIR}/resource_usage.log"
    
    echo "Unit tests completed in ${duration} seconds"
}

# Run integration tests
run_integration_tests() {
    echo "Running integration tests..."
    
    # Setup test context
    export GUARDIAN_TEST_CONFIG="$(pwd)/config/test_config.yaml"
    
    # Run security tests
    cargo test --test security_tests \
        --features integration \
        -- \
        --test-threads=1 \
        --nocapture \
        2>&1 | tee "${METRICS_DIR}/security_tests.log"
        
    # Run ML tests
    if [ "${GPU_ENABLED}" = "true" ]; then
        GUARDIAN_GPU_ENABLED=1 cargo test --test ml_tests \
            --features integration \
            -- \
            --test-threads=1 \
            --nocapture \
            2>&1 | tee "${METRICS_DIR}/ml_tests.log"
    else
        cargo test --test ml_tests \
            --features integration \
            -- \
            --test-threads=1 \
            --nocapture \
            2>&1 | tee "${METRICS_DIR}/ml_tests.log"
    fi
    
    # Run storage tests
    cargo test --test storage_tests \
        --features integration \
        -- \
        --test-threads=1 \
        --nocapture \
        2>&1 | tee "${METRICS_DIR}/storage_tests.log"
}

# Run benchmarks
run_benchmarks() {
    echo "Running performance benchmarks..."
    
    # Security benchmarks
    cargo bench --bench security_bench \
        -- \
        --warm-up-time 5 \
        --measurement-time 30 \
        --sample-size 100 \
        2>&1 | tee "${METRICS_DIR}/security_bench.log"
        
    # ML benchmarks with GPU if available
    if [ "${GPU_ENABLED}" = "true" ]; then
        GUARDIAN_GPU_ENABLED=1 cargo bench --bench ml_bench \
            -- \
            --warm-up-time 5 \
            --measurement-time 30 \
            --sample-size 100 \
            2>&1 | tee "${METRICS_DIR}/ml_bench.log"
    else
        cargo bench --bench ml_bench \
            -- \
            --warm-up-time 5 \
            --measurement-time 30 \
            --sample-size 100 \
            2>&1 | tee "${METRICS_DIR}/ml_bench.log"
    fi
}

# Cleanup test artifacts
cleanup() {
    echo "Cleaning up test environment..."
    
    # Stop resource monitoring
    if [ -n "${MONITOR_PID:-}" ]; then
        kill "${MONITOR_PID}" || true
    fi
    
    # Generate test report
    {
        echo "Test Summary Report"
        echo "=================="
        echo "Date: $(date)"
        echo ""
        echo "Unit Tests:"
        grep -A 1 "test result" "${METRICS_DIR}/unit_tests.log" || true
        echo ""
        echo "Integration Tests:"
        for test_log in security_tests ml_tests storage_tests; do
            echo "${test_log}:"
            grep -A 1 "test result" "${METRICS_DIR}/${test_log}.log" || true
        done
        echo ""
        echo "Benchmarks:"
        echo "See detailed reports in ${BENCH_DIR}"
    } > "${METRICS_DIR}/test_report.txt"
    
    # Archive test results
    tar -czf "${METRICS_DIR}/test_results.tar.gz" \
        -C "${METRICS_DIR}" \
        .
        
    # Cleanup temporary files
    rm -f "${METRICS_DIR}"/*.log
    
    echo "Cleanup complete"
}

# Check resource usage against limits
check_resource_usage() {
    local usage_log="$1"
    
    # Extract CPU and memory usage
    local cpu_usage=$(awk '{sum += $13} END {print sum/NR}' "${usage_log}")
    local mem_usage=$(awk '{sum += $4} END {print sum/NR}' "${usage_log}")
    
    # Compare against limits
    local cpu_limit=$(echo "${RESOURCE_LIMITS}" | grep -o "cpu=[0-9]*" | cut -d= -f2)
    local mem_limit=$(echo "${RESOURCE_LIMITS}" | grep -o "memory=[0-9]*G" | cut -d= -f2 | tr -d G)
    
    if (( $(echo "${cpu_usage} > ${cpu_limit}" | bc -l) )); then
        echo "Warning: CPU usage (${cpu_usage}%) exceeded limit (${cpu_limit}%)"
    fi
    
    if (( $(echo "${mem_usage}/1024/1024 > ${mem_limit}" | bc -l) )); then
        echo "Warning: Memory usage (${mem_usage}MB) exceeded limit (${mem_limit}GB)"
    fi
}

# Main execution
main() {
    setup_test_env
    
    # Run tests
    run_unit_tests
    run_integration_tests
    run_benchmarks
    
    # Cleanup
    cleanup
    
    echo "All tests completed successfully"
}

main "$@"