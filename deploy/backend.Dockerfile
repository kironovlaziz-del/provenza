# syntax=docker/dockerfile:1.7
# Provenza backend image: FastAPI API, Celery worker, Celery beat and the
# migration job all run from this one image (the command picks the role).
# Build context: repository root (see deploy/docker-compose.yml).

ARG PYTHON_VERSION=3.12

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
# English NER model for the Prompt Firewall (PII masking of names,
# organizations, places). Pinned to the spaCy 3.8 series.
ARG SPACY_EN_MODEL_URL=https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl
RUN pip install "${SPACY_EN_MODEL_URL}"

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
RUN chmod 0755 /usr/local/bin/provenza-entrypoint \
 && rm -f /app/apply_*.py /app/celerybeat-schedule \
 && mkdir -p /app/data /app/run \
 && chown -R provenza:provenza /app/data /app/run
USER provenza
EXPOSE 8000
ENTRYPOINT ["tini", "--", "provenza-entrypoint"]
CMD ["api"]
