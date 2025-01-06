# Stage 1: Prometheus Base
FROM prom/prometheus:v2.45.0 as prometheus-base

# Copy prometheus configuration
COPY infrastructure/config/prometheus.yml /etc/prometheus/prometheus.yml

# Create directories for rules and certificates
RUN mkdir -p /etc/prometheus/rules /etc/prometheus/certs

# Set up optimized storage settings
RUN mkdir -p /prometheus && \
    chown -R nobody:nobody /prometheus /etc/prometheus

# Configure security settings
USER nobody
EXPOSE 9090

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/-/healthy || exit 1

# Stage 2: Grafana Base
FROM grafana/grafana:9.5.0 as grafana-base

# Copy grafana configuration
COPY infrastructure/config/grafana.json /etc/grafana/grafana.json

# Create required directories
RUN mkdir -p /var/lib/grafana/dashboards /etc/grafana/provisioning/datasources

# Set up security configurations
ENV GF_SECURITY_ALLOW_EMBEDDING=false \
    GF_SECURITY_COOKIE_SECURE=true \
    GF_SECURITY_COOKIE_SAMESITE=strict \
    GF_SECURITY_DISABLE_GRAVATAR=true \
    GF_USERS_ALLOW_SIGN_UP=false

USER grafana
EXPOSE 3000

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

# Stage 3: Alertmanager Base
FROM prom/alertmanager:v0.25.0 as alertmanager-base

# Copy alertmanager configuration
COPY infrastructure/config/alertmanager.yml /etc/alertmanager/alertmanager.yml

# Create directories for certificates
RUN mkdir -p /etc/alertmanager/certs

# Set up security configurations
USER nobody
EXPOSE 9093

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9093/-/healthy || exit 1

# Stage 4: Final Image
FROM scratch

# Copy necessary files from previous stages
COPY --from=prometheus-base /prometheus /prometheus
COPY --from=prometheus-base /etc/prometheus /etc/prometheus
COPY --from=prometheus-base /bin/prometheus /bin/prometheus
COPY --from=prometheus-base /bin/promtool /bin/promtool

COPY --from=grafana-base /var/lib/grafana /var/lib/grafana
COPY --from=grafana-base /usr/share/grafana /usr/share/grafana
COPY --from=grafana-base /etc/grafana /etc/grafana

COPY --from=alertmanager-base /alertmanager /alertmanager
COPY --from=alertmanager-base /etc/alertmanager /etc/alertmanager
COPY --from=alertmanager-base /bin/alertmanager /bin/alertmanager

# Set up volumes
VOLUME ["/prometheus", "/var/lib/grafana", "/alertmanager"]

# Security configurations
USER nobody
WORKDIR /prometheus

# Resource limits
ENV PROMETHEUS_STORAGE_MAX_BLOCKS=50 \
    PROMETHEUS_STORAGE_RETENTION_TIME=15d \
    GRAFANA_MEMORY_LIMIT=1g \
    ALERTMANAGER_MEMORY_LIMIT=512m

# Expose ports
EXPOSE 9090 3000 9093

# Set entrypoint
ENTRYPOINT ["/bin/prometheus", \
    "--config.file=/etc/prometheus/prometheus.yml", \
    "--storage.tsdb.path=/prometheus", \
    "--web.console.libraries=/usr/share/prometheus/console_libraries", \
    "--web.console.templates=/usr/share/prometheus/consoles", \
    "--web.enable-lifecycle", \
    "--storage.tsdb.retention.time=15d", \
    "--storage.tsdb.retention.size=50GB", \
    "--web.enable-admin-api=false"]

# Default command
CMD ["--web.listen-address=:9090"]

# Labels
LABEL maintainer="AI Guardian Team" \
      version="1.0.0" \
      description="AI Guardian Monitoring Stack" \
      security.capabilities.drop="ALL" \
      security.capabilities.add="NET_BIND_SERVICE" \
      io.k8s.description="Monitoring stack for AI Guardian system" \
      io.k8s.display-name="AI Guardian Monitor"