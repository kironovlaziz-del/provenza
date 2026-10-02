# Isolated training runner.
#
# This image contains only what a training job needs - torch, transformers,
# peft, scikit-learn - plus a tiny entrypoint. The Celery worker on the
# host launches one container per job, so a crash or OOM inside a job
# cannot take down the queue.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/cache/huggingface \
    TRANSFORMERS_OFFLINE=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install CPU torch first (swap to the CUDA wheel index on a GPU host).
RUN pip install --no-cache-dir \
    torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt /app/training_runner/requirements.txt
RUN pip install --no-cache-dir -r /app/training_runner/requirements.txt

# Copy the application code needed by the runner. Only the parts that do
# not require the full backend environment (services, models, schemas,
# workers) are included.
COPY app /app/app
COPY training_runner/run_training.py /app/training_runner/run_training.py

# Optional: download the spaCy NER model so the Prompt Firewall works
# consistently inside the container. Uncomment if you enable
# PROMPT_FIREWALL_NER_ENABLED in the container environment.
# RUN python -m spacy download en_core_web_sm

# Datasets and models are mounted at runtime by the launcher; the container
# itself is stateless.
VOLUME ["/app/data", "/cache/huggingface"]

ENTRYPOINT ["python", "-m", "training_runner.run_training"]
