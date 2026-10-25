# syntax=docker/dockerfile:1.7
# Provenza backend image: FastAPI API, Celery worker, Celery beat and the
# migration job all run from this one image (the command picks the role).
# Build context: repository root (deploy/scripts/lib.sh build_images).

ARG PYTHON_VERSION=3.12
ARG GO_VERSION=1.27

# ------------------------------------------------------------- sensor stage
# The egress sensor, served by the API at /api/v1/egress-sensor/download/
# (app/api/sensor_download.py): a host installs the sensor that matches this
# control plane. The BPF object is embedded, so this is a plain Go build.
FROM docker.io/library/golang:${GO_VERSION} AS sensor
WORKDIR /src
COPY sensor/go.mod sensor/go.sum ./
RUN go mod download
COPY sensor/ ./
ARG SENSOR_VERSION=control-plane
RUN set -eu; mkdir -p /dist; \
    for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
        -ldflags "-s -w -X main.version=${SENSOR_VERSION}" \
        -o /dist/provenza-sensor-linux-$arch ./cmd/provenza-sensor; \
    done; \
    cp install.sh packaging/provenzasensor.service /dist/; \
    cd /dist && sha256sum provenza-sensor-linux-* install.sh provenzasensor.service > SHA256SUMS

# --------------------------------------------------------------- edge stage
# The egress proxy and the endpoint agent, for the hosts that run them: this
# one (deploy/scripts/edge.sh puts them in place when installing or
# upgrading) and any other (served next to the sensor, below).
FROM docker.io/library/golang:${GO_VERSION} AS edge
WORKDIR /src
COPY agent/go.mod agent/go.sum ./agent/
RUN cd agent && go mod download
COPY proxy/ ./proxy/
COPY agent/ ./agent/
RUN set -eu; mkdir -p /dist; \
    for arch in amd64 arm64; do \
      (cd proxy && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w" \
        -o /dist/provenza-proxy-linux-$arch .); \
      (cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w" \
        -o /dist/provenza-agent-linux-$arch .); \
    done; \
    cd /dist && sha256sum provenza-proxy-linux-* provenza-agent-linux-* > SHA256SUMS.edge

# ---------------------------------------------------------------- build stage
FROM python:${PYTHON_VERSION}-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libpq-dev \
 && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# -------------------------------------------------------------- runtime stage
FROM python:${PYTHON_VERSION}-slim AS runtime
LABEL org.opencontainers.image.title="Provenza backend" \
      org.opencontainers.image.source="https://github.com/kironovlaziz-del/provenza" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 provenza \
 && useradd --system --uid 10001 --gid provenza --home-dir /app --shell /usr/sbin/nologin provenza
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    ENVIRONMENT=production \
    EXTENSION_TEMPLATE_DIR=/opt/provenza/extension
WORKDIR /app
COPY backend/ /app/
COPY extension/ /opt/provenza/extension/
COPY deploy/backend-entrypoint.sh /usr/local/bin/provenza-entrypoint
COPY --from=sensor /dist/ /app/sensor-dist/
COPY --from=edge /dist/ /tmp/edge-dist/
RUN cd /tmp/edge-dist && cp provenza-proxy-linux-* provenza-agent-linux-* /app/sensor-dist/ \
 && cat SHA256SUMS.edge >> /app/sensor-dist/SHA256SUMS && rm -rf /tmp/edge-dist
RUN chmod 0755 /usr/local/bin/provenza-entrypoint \
 && rm -f /app/apply_*.py /app/celerybeat-schedule \
 && mkdir -p /app/data /app/run \
 && chown -R provenza:provenza /app/data /app/run
USER provenza
EXPOSE 8000
ENTRYPOINT ["tini", "--", "provenza-entrypoint"]
CMD ["api"]
