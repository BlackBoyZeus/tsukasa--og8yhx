# Start with official Temporal server base image
FROM temporalio/server:1.20

# Set environment variables
ENV TEMPORAL_NAMESPACE=guardian \
    TEMPORAL_TLS_ENABLED=true \
    TEMPORAL_PERSISTENCE_DEFAULT=postgresql \
    TEMPORAL_SECURITY_ENABLED=true \
    TEMPORAL_METRICS_PROMETHEUS_ENABLED=true \
    TEMPORAL_RESOURCE_MAX_CONCURRENT_WORKFLOWS=1000 \
    TEMPORAL_LOG_LEVEL=info

# Install required FreeBSD packages and security updates
RUN pkg update && pkg install -y \
    ca_root_nss \
    openssl \
    prometheus \
    postgresql14-client \
    curl \
    && pkg clean -y \
    && rm -rf /var/cache/pkg/*

# Create necessary directories with secure permissions
RUN mkdir -p /etc/temporal/config \
    /etc/temporal/tls \
    /var/lib/temporal \
    /var/lib/temporal/backup \
    /var/log/temporal \
    && chown -R temporal:temporal /etc/temporal \
    /var/lib/temporal \
    /var/log/temporal \
    && chmod 750 /etc/temporal \
    /var/lib/temporal \
    /var/log/temporal

# Copy configuration files
COPY src/backend/temporal.yaml /etc/temporal/config/temporal.yaml

# Configure TLS certificates
RUN mkdir -p /etc/temporal/tls/certs \
    && chmod 700 /etc/temporal/tls/certs

# Set up Prometheus metrics endpoint
COPY --from=prom/prometheus:v2.45 /bin/prometheus /bin/prometheus
COPY --from=prom/prometheus:v2.45 /etc/prometheus/prometheus.yml /etc/prometheus/prometheus.yml

# Configure security policies
RUN echo "security.bsd.unprivileged_proc_debug=0" >> /etc/sysctl.conf \
    && echo "security.bsd.see_other_uids=0" >> /etc/sysctl.conf \
    && echo "kern.randompid=1" >> /etc/sysctl.conf

# Set up health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD temporal-server health && curl -f http://localhost:9090/-/healthy || exit 1

# Expose required ports
EXPOSE 7233 7234 7235 7239 9090

# Set resource limits
RUN ulimit -n 65535 \
    && ulimit -u 2048

# Set security options
RUN chmod 400 /etc/temporal/config/temporal.yaml \
    && chmod 500 /usr/local/bin/temporal-server

# Create non-root user
RUN adduser -D temporal \
    && chown -R temporal:temporal /etc/temporal \
    /var/lib/temporal \
    /var/log/temporal

USER temporal

# Set up volumes for persistence
VOLUME [ \
    "/etc/temporal/config", \
    "/etc/temporal/tls", \
    "/var/lib/temporal", \
    "/var/lib/temporal/backup", \
    "/var/log/temporal" \
]

# Start Temporal server with security configurations
CMD ["temporal-server", "--env", "prod", \
     "--config", "/etc/temporal/config/temporal.yaml", \
     "--tls-cert-file", "/etc/temporal/tls/certs/temporal.crt", \
     "--tls-key-file", "/etc/temporal/tls/certs/temporal.key"]