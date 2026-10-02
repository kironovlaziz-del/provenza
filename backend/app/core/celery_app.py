from celery import Celery
from app.core.config import settings

redis_url = f"redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}:{settings.REDIS_PORT}/0"

celery_app = Celery(
    "ai_control_tower",
    broker=redis_url,
    backend=redis_url.replace("/0", "/1"),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,

    # Task time limits protect against a runaway training job that would
    # otherwise pin the worker indefinitely. soft_limit raises a Python
    # exception the task can catch; the hard limit sends SIGKILL.
    task_soft_time_limit=3600,     # 1 hour
    task_time_limit=3900,          # 1 hour 5 minutes

    # Acknowledging only after the task finishes (instead of when it is
    # delivered) means a worker that crashes mid-task does not silently
    # lose the job - the broker will redeliver it.
    task_acks_late=True,
    task_reject_on_worker_lost=True,

    # Prefetching a batch of messages is fine for tiny tasks but disastrous
    # for long-running ones: one worker grabs up to N tasks and blocks the
    # rest of the queue while it churns through the first one.
    worker_prefetch_multiplier=1,
)

# Scheduled (beat) tasks. Requires a running `celery beat` process
# (systemd unit ai-ct-celery-beat) in addition to the worker.
from celery.schedules import crontab  # noqa: E402

celery_app.conf.beat_schedule = {
    # liveness of the schedule -> queue -> worker path (System status page)
    "system-heartbeat": {
        "task": "system.heartbeat",
        "schedule": 60.0,
    },
    # Re-verify every stored service connection (AD/LDAP bind, DNS reach)
    # a few times a day, so the UI reflects whether saved credentials
    # still work. Staggered to a quiet minute rather than exactly on the
    # hour.
    "reverify-service-connections": {
        "task": "discovery.reverify_connections",
        "schedule": crontab(minute=17, hour="*/6"),  # 00:17, 06:17, 12:17, 18:17 UTC
    },
    # Request pipeline time limits: expire queued / unanswered requests, fail
    # requests whose worker was lost, wipe raw prompts past retention.
    "sweep-request-queue": {
        "task": "requests.sweep",
        "schedule": crontab(minute="*/5"),
    },
}

from app.workers import (  # noqa: E402,F401
    request_tasks,
    training_tasks,
    telemetry_tasks,
    discovery_tasks,
    queue_tasks,
    byok_tasks,
    system_tasks,
)


