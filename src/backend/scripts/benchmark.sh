#!/usr/bin/env bash

# Guardian System Benchmark Script
# Version: 1.0.0
# Executes comprehensive performance benchmarks across all system components

set -euo pipefail
IFS=$'\n\t'

# Global configuration
BENCH_RESULTS_DIR="${PWD}/benchmark_results"
CRITERION_CONFIG="${PWD}/.criterion"
BENCH_TIMEOUT=3600
LOG_LEVEL="info"
JAIL_NAME="guardian_bench"
GPU_DEVICE="/dev/nvidia0"
HSM_CONFIG="${PWD}/hsm.conf"

# Ensure benchmark environment is clean
cleanup() {
    echo "Cleaning up benchmark environment..."
    
    # Remove benchmark jail if exists
    if jls | grep -q "${JAIL_NAME}"; then
        jail -r "${JAIL_NAME}"
    fi

    # Clear GPU memory
    if [ -e "${GPU_DEVICE}" ]; then
        nvidia-smi --gpu-reset
    fi

    # Reset HSM state
    if [ -f "${HSM_CONFIG}" ]; then
        pkcs11-tool --module="${HSM_CONFIG}" --login --reset
    fi

    # Clean criterion artifacts
    if [ -d "${CRITERION_CONFIG}" ]; then
        rm -rf "${CRITERION_CONFIG}"
    fi

    # Reset system counters
    sysctl kern.cp_time=0

    echo "Cleanup completed"
}

# Set up isolated benchmark environment
setup_benchmark_env() {
    echo "Setting up benchmark environment..."

    # Create results directory
    mkdir -p "${BENCH_RESULTS_DIR}"

    # Create isolated jail for benchmarking
    cat > /etc/jail.conf.d/benchmark.conf << EOF
${JAIL_NAME} {
    path = "/usr/jail/${JAIL_NAME}";
    mount.devfs;
    allow.raw_sockets;
    allow.sysvipc;
    exec.start = "/bin/sh /etc/rc";
    exec.stop = "/bin/sh /etc/rc.shutdown";
    persist;
}
EOF

    # Initialize jail
    jail -c "${JAIL_NAME}"

    # Configure resource limits
    rctl -a jail:${JAIL_NAME}:vmemoryuse:deny=4G
    rctl -a jail:${JAIL_NAME}:pcpu:deny=80
    rctl -a jail:${JAIL_NAME}:maxproc:deny=1000

    # Set up performance counters
    sysctl kern.cp_times=1
    sysctl kern.timecounter.hardware=HPET

    # Initialize criterion config
    mkdir -p "${CRITERION_CONFIG}"
    cat > "${CRITERION_CONFIG}/criterion.toml" << EOF
sample_size = 100
measurement_time = 10
warm_up_time = 3
confidence_level = 0.95
significance_level = 0.05
noise_threshold = 0.01
EOF

    echo "Benchmark environment ready"
}

# Execute security benchmarks
run_security_benchmarks() {
    echo "Running security benchmarks..."

    # Run security component benchmarks
    cargo bench --bench security_bench -- \
        --verbose \
        --color always \
        --measurement-time 30 \
        --sample-size 100 \
        --output "${BENCH_RESULTS_DIR}/security"

    # Validate results
    if [ $? -ne 0 ]; then
        echo "Security benchmarks failed"
        return 1
    fi

    echo "Security benchmarks completed"
}

# Execute ML benchmarks
run_ml_benchmarks() {
    echo "Running ML benchmarks..."

    # Check GPU availability
    if [ -e "${GPU_DEVICE}" ]; then
        export CUDA_VISIBLE_DEVICES=0
    else
        export CUDA_VISIBLE_DEVICES=""
    fi

    # Run ML component benchmarks
    cargo bench --bench ml_bench -- \
        --verbose \
        --color always \
        --measurement-time 30 \
        --sample-size 100 \
        --output "${BENCH_RESULTS_DIR}/ml"

    # Validate results
    if [ $? -ne 0 ]; then
        echo "ML benchmarks failed"
        return 1
    fi

    echo "ML benchmarks completed"
}

# Execute storage benchmarks
run_storage_benchmarks() {
    echo "Running storage benchmarks..."

    # Run storage component benchmarks
    cargo bench --bench storage_bench -- \
        --verbose \
        --color always \
        --measurement-time 30 \
        --sample-size 100 \
        --output "${BENCH_RESULTS_DIR}/storage"

    # Validate results
    if [ $? -ne 0 ]; then
        echo "Storage benchmarks failed"
        return 1
    fi

    echo "Storage benchmarks completed"
}

# Generate comprehensive benchmark report
generate_report() {
    echo "Generating benchmark report..."

    # Aggregate results
    criterion-report \
        --input "${BENCH_RESULTS_DIR}" \
        --output "${BENCH_RESULTS_DIR}/report.html" \
        --template comprehensive

    # Add system information
    {
        echo "System Information:"
        echo "CPU: $(sysctl -n hw.model)"
        echo "Memory: $(sysctl -n hw.physmem | awk '{print $1/1024/1024/1024 "GB"}')"
        echo "OS: $(uname -sr)"
        if [ -e "${GPU_DEVICE}" ]; then
            echo "GPU: $(nvidia-smi --query-gpu=name --format=csv,noheader)"
        fi
    } >> "${BENCH_RESULTS_DIR}/system_info.txt"

    # Generate graphs
    criterion-plot \
        --input "${BENCH_RESULTS_DIR}" \
        --output "${BENCH_RESULTS_DIR}/plots"

    # Sign report
    if [ -f "${HSM_CONFIG}" ]; then
        openssl dgst -sha256 -sign "${HSM_CONFIG}" \
            -out "${BENCH_RESULTS_DIR}/report.sig" \
            "${BENCH_RESULTS_DIR}/report.html"
    fi

    echo "Report generated: ${BENCH_RESULTS_DIR}/report.html"
}

# Main execution
main() {
    # Trap cleanup
    trap cleanup EXIT

    # Setup environment
    setup_benchmark_env

    # Run benchmarks with timeout
    timeout ${BENCH_TIMEOUT} bash -c '
        run_security_benchmarks && \
        run_ml_benchmarks && \
        run_storage_benchmarks
    '

    # Generate report
    generate_report

    echo "Benchmark suite completed successfully"
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi