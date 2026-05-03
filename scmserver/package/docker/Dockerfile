FROM scratch

ARG VERSION

LABEL org.opencontainers.image.title="OpenSCM Server" \
      org.opencontainers.image.description="Privacy-first security compliance management" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="OpenSCM" \
      org.opencontainers.image.url="https://openscm.io" \
      org.opencontainers.image.documentation="https://openscm.io" \
      org.opencontainers.image.source="https://github.com/yarivha/OpenSCM" \
      org.opencontainers.image.licenses="FSL-1.1-ALv2"

# Binary is staged at the build context root by the CI workflow
COPY scmserver /usr/bin/scmserver

EXPOSE 8000

VOLUME ["/etc/openscm", "/var/lib/openscm"]

CMD ["/usr/bin/scmserver"]
