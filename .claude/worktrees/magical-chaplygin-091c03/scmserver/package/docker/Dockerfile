FROM scratch

ARG VERSION
ARG RELEASE
ARG TARGET

LABEL org.opencontainers.image.title="OpenSCM Server" \
      org.opencontainers.image.description="Privacy-first security compliance management" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="OpenSCM" \
      org.opencontainers.image.url="https://openscm.io" \
      org.opencontainers.image.documentation="https://openscm.io" \
      org.opencontainers.image.source="https://github.com/yarivha/OpenSCM" \
      org.opencontainers.image.licenses="FSL-1.1-ALv2"

COPY target/${TARGET}/release/scmserver /usr/bin/scmserver

EXPOSE 8000

VOLUME ["/etc/openscm", "/var/lib/openscm"]

CMD ["/usr/bin/scmserver"]
