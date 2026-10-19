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

    # Task time limits protect against a runaway task that would
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

# Scheduled (beat) tasks. Requires a running `celery beat` process (the
# beat service: provenza-beat, or `beat` in docker-compose.dev.yml) in
# addition to the worker.
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
    # Retention of agent telemetry: old policy checks deleted, old agent
    # content erased (app/services/retention.py).
    "retention-run": {
        "task": "retention.run",
        "schedule": crontab(minute="*/5"),
    },
    # Sign a checkpoint (Merkle root) of every audit log that grew since its
    # last one - what proofs and offline verification are anchored to.
    "audit-checkpoints": {
        "task": "audit.checkpoint",
        "schedule": crontab(minute="2-59/5"),
    },
    # Time-stamp new checkpoints with each organization's TSA (RFC 3161),
    # two minutes after they are signed (app/services/audit_witness.py).
    "audit-timestamps": {
        "task": "audit.timestamp",
        "schedule": crontab(minute="4-59/5"),
    },
    # Commit recorded agent actions to the audit log in batches (one record
    # per organization and run), so the next checkpoint covers them and
    # PVP receipts are provable offline (app/pvp/seal.py).
    "pvp-seal-actions": {
        "task": "pvp.seal_actions",
        "schedule": 60.0,
    },
    # Drop nonces of signed action requests past their freshness window.
    "pvp-prune-nonces": {
        "task": "pvp.prune_nonces",
        "schedule": crontab(minute=23),
    },
    # Old egress checks; each agent's latest verdict stays.
    "pvp-prune-egress-checks": {
        "task": "pvp.prune_egress_checks",
        "schedule": crontab(hour=4, minute=37),
    },
    # Warn once per silent egress sensor: it has sent at least one heartbeat
    # and missed three since (at least 5 minutes, metrics.offline_after). Runs every 5 minutes,
    # staggered after the audit checkpoint (minute 2) and timestamp (minute 4).
    "egress-sensor-offline": {
        "task": "egress_sensor.warn_offline",
        "schedule": crontab(minute="3-59/5"),
    },
    # Prune sampled allowed connections older than each organization's
    # retention (EgressPolicySettings.activity_retention_days). Runs hourly
    # at minute 41 — a quiet minute, not competing with other jobs.
    "egress-sensor-prune-activity": {
        "task": "egress_sensor.prune_activity",
        "schedule": crontab(minute=41),
    },
    # Same shape, for the violations table. Runs six minutes after the
    # activity task so the two do not contend for the same tables.
    "egress-sensor-prune-violations": {
        "task": "egress_sensor.prune_violations",
        "schedule": crontab(minute=47),
    },
    # Mark queued commands whose TTL has passed as expired. Runs every
    # minute: the TTL is 5 minutes, so the flag is a few tens of seconds
    # behind, which is exactly what the UI wants to show.
    "egress-sensor-expire-commands": {
        "task": "egress_sensor.expire_commands",
        "schedule": crontab(minute="*"),
    },
}

from app.workers import (  # noqa: E402,F401
    telemetry_tasks,
    discovery_tasks,
    retention_tasks,
    byok_tasks,
    system_tasks,
    audit_tasks,
    pvp_tasks,
    egress_sensor_commands_tasks,
    egress_sensor_tasks,
)


