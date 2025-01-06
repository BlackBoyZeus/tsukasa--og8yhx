#!/usr/bin/env bash

# AI Guardian Backend Deployment Script
# Version: 1.0.0
# Description: Enterprise-grade deployment script for AI Guardian backend services

set -euo pipefail
IFS=$'\n\t'

# Environment and version configuration
DEPLOY_ENV=${DEPLOY_ENV:-production}
APP_VERSION=${APP_VERSION:-latest}
DOCKER_REGISTRY="guardian.registry.local"
MAX_DEPLOY_TIME=300
HEALTH_CHECK_INTERVAL=5
CANARY_PERCENTAGE=5
RESOURCE_THRESHOLD=5
ROLLBACK_TIMEOUT=60
TPM_VERIFICATION_TIMEOUT=30
TEMPORAL_NAMESPACE="guardian-deployment"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a /var/log/guardian/deploy.log
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a /var/log/guardian/deploy.log
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a /var/log/guardian/deploy.log
}

# Error handling
handle_error() {
    local exit_code=$?
    local line_no=$1
    log_error "Deployment failed at line ${line_no} with exit code ${exit_code}"
    rollback_deployment
    exit ${exit_code}
}
trap 'handle_error ${LINENO}' ERR

# Validate deployment environment
validate_environment() {
    log_info "Validating deployment environment..."

    # Source setup script for system requirement checks
    source ./setup.sh
    check_system_requirements || {
        log_error "System requirements validation failed"
        return 1
    }

    # Verify TPM state
    timeout ${TPM_VERIFICATION_TIMEOUT} tpm2_getcap -l || {
        log_error "TPM verification failed"
        return 1
    }

    # Check FreeBSD jail configuration
    jls >/dev/null || {
        log_error "FreeBSD jail subsystem not available"
        return 1
    }

    # Verify Temporal.io connectivity
    temporal operator namespace list | grep -q "${TEMPORAL_NAMESPACE}" || {
        log_error "Temporal.io namespace not accessible"
        return 1
    }

    # Verify Docker daemon status
    docker info >/dev/null || {
        log_error "Docker daemon not running"
        return 1
    }

    log_info "Environment validation completed successfully"
    return 0
}

# Deploy services using blue-green deployment
deploy_services() {
    local version=$1
    log_info "Starting deployment of version ${version}"

    # Create new deployment namespace
    local deploy_id="guardian-${version}-$(date +%s)"
    local blue_ns="blue-${deploy_id}"
    local green_ns="green-${deploy_id}"

    # Deploy to green environment
    log_info "Deploying to green environment..."
    docker-compose -f docker-compose.yml -p ${green_ns} up -d || {
        log_error "Failed to deploy green environment"
        return 1
    }

    # Wait for services to be ready
    local timeout=${MAX_DEPLOY_TIME}
    while ((timeout > 0)); do
        if check_deployment_health ${green_ns}; then
            log_info "Green deployment healthy"
            break
        fi
        sleep ${HEALTH_CHECK_INTERVAL}
        ((timeout-=HEALTH_CHECK_INTERVAL))
    done

    if ((timeout <= 0)); then
        log_error "Deployment health check timed out"
        rollback_deployment ${green_ns}
        return 1
    }

    # Deploy canary
    log_info "Starting canary deployment (${CANARY_PERCENTAGE}%)"
    if ! deploy_canary ${green_ns} ${CANARY_PERCENTAGE}; then
        log_error "Canary deployment failed"
        rollback_deployment ${green_ns}
        return 1
    }

    # Progressive traffic shift
    log_info "Starting progressive traffic shift"
    for percentage in 25 50 75 100; do
        if ! shift_traffic ${green_ns} ${percentage}; then
            log_error "Traffic shift failed at ${percentage}%"
            rollback_deployment ${green_ns}
            return 1
        }
        sleep ${HEALTH_CHECK_INTERVAL}
    done

    # Cleanup old deployment
    if docker-compose ls -q | grep -q "blue-"; then
        log_info "Removing old deployment"
        docker-compose -f docker-compose.yml -p ${blue_ns} down
    fi

    log_info "Deployment completed successfully"
    return 0
}

# Check deployment health
check_deployment_health() {
    local namespace=$1
    local healthy=true

    # Check service health
    for service in backend temporal redis prometheus; do
        if ! docker-compose -f docker-compose.yml -p ${namespace} ps ${service} | grep -q "Up"; then
            log_error "Service ${service} is not healthy"
            healthy=false
            break
        fi
    done

    # Check resource usage
    local cpu_usage=$(docker stats --no-stream --format "{{.CPUPerc}}" | tr -d '%' | awk '{sum+=$1} END {print sum}')
    if (( $(echo "${cpu_usage} > ${RESOURCE_THRESHOLD}" | bc -l) )); then
        log_error "CPU usage exceeds threshold: ${cpu_usage}%"
        healthy=false
    fi

    # Verify Temporal workflows
    if ! temporal workflow list -n ${TEMPORAL_NAMESPACE} >/dev/null 2>&1; then
        log_error "Temporal workflows not accessible"
        healthy=false
    }

    ${healthy}
}

# Deploy canary instance
deploy_canary() {
    local namespace=$1
    local percentage=$2
    log_info "Deploying canary with ${percentage}% traffic"

    # Configure canary routing
    if ! update_routing_config ${namespace} ${percentage}; then
        return 1
    }

    # Monitor canary metrics
    local start_time=$(date +%s)
    local timeout=300
    while (($(date +%s) - start_time < timeout)); do
        if ! check_canary_health ${namespace}; then
            log_error "Canary health check failed"
            return 1
        fi
        sleep ${HEALTH_CHECK_INTERVAL}
    done

    return 0
}

# Rollback deployment
rollback_deployment() {
    local namespace=$1
    log_warn "Initiating rollback for ${namespace}"

    # Stop new deployment
    docker-compose -f docker-compose.yml -p ${namespace} down || true

    # Restore traffic to previous version
    if docker-compose ls -q | grep -q "blue-"; then
        log_info "Restoring traffic to previous version"
        shift_traffic "blue-*" 100
    fi

    # Cleanup failed deployment
    docker-compose -f docker-compose.yml -p ${namespace} rm -f || true

    log_info "Rollback completed"
}

# Update routing configuration
update_routing_config() {
    local namespace=$1
    local percentage=$2

    # Update load balancer configuration
    local config_file="/etc/guardian/routing.conf"
    sed -i '' "s/upstream_weight.*/upstream_weight ${percentage};/" ${config_file} || return 1

    # Reload configuration
    service nginx reload || return 1

    return 0
}

# Main deployment function
main() {
    log_info "Starting AI Guardian deployment process"

    # Validate environment
    validate_environment || exit 1

    # Deploy services
    deploy_services ${APP_VERSION} || exit 1

    # Verify deployment
    if ! check_deployment_health "green-*"; then
        log_error "Final deployment verification failed"
        rollback_deployment "green-*"
        exit 1
    fi

    log_info "Deployment process completed successfully"
}

# Execute main function
main
```

This deployment script provides a robust, zero-downtime deployment solution for the AI Guardian backend services with the following key features:

1. Blue-green deployment strategy with canary testing
2. Comprehensive health checks and monitoring
3. Progressive traffic shifting
4. Automatic rollback on failure
5. Resource usage monitoring
6. TPM verification
7. Temporal.io workflow integration
8. Detailed logging and error handling
9. Environment validation
10. FreeBSD jail and Docker integration

The script follows enterprise deployment best practices including:
- Strict error handling
- Comprehensive logging
- Security validations
- Resource monitoring
- Zero-downtime updates
- Automated rollback procedures
- Canary deployment
- Progressive traffic shifting
- Health monitoring
- Performance impact assessment

Make the script executable with:
```bash
chmod +x deploy.sh
```

Run with environment and version specification:
```bash
DEPLOY_ENV=production APP_VERSION=1.0.0 ./deploy.sh