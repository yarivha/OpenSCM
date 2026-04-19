FROM debian:bookworm-slim

ARG VERSION
ARG RELEASE
ARG TARGETARCH

LABEL org.opencontainers.image.title="OpenSCM Server" \
      org.opencontainers.image.description="Privacy-first security compliance management" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="OpenSCM" \
      org.opencontainers.image.url="https://openscm.io" \
      org.opencontainers.image.documentation="https://openscm.io" \
      org.opencontainers.image.source="https://github.com/yarivha/OpenSCM" \
      org.opencontainers.image.licenses="FSL-1.1-ALv2"

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false -m -d /var/lib/openscm openscm

# Create directories
RUN mkdir -p /etc/openscm/keys \
    && mkdir -p /var/lib/openscm \
    && chown -R openscm:openscm /etc/openscm \
    && chown -R openscm:openscm /var/lib/openscm

# Copy architecture-specific binary
COPY docker-stage/${TARGETARCH}/scmserver /usr/bin/scmserver
RUN chmod +x /usr/bin/scmserver

USER openscm

EXPOSE 8000

VOLUME ["/etc/openscm", "/var/lib/openscm"]

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/login || exit 1

CMD ["/usr/bin/scmserver"]
