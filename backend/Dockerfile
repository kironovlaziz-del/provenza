# ---- Provenza — backend (FastAPI + Celery) ----
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# system deps: postgres client (pg_isready / psql for entrypoint wait), build tools for some wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
        postgresql-client gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# entrypoint waits for DB, runs migrations, seeds a demo admin, then starts uvicorn
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/docker-entrypoint.sh"]
