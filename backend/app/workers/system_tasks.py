"""
Beat heartbeat: scheduled by Celery beat every minute and run by a worker,
it leaves a timestamp in Redis. Its age is how system_health tells that the
schedule -> queue -> worker path works.
"""

import time

from app.core.celery_app import celery_app
from app.core.config import settings


@celery_app.task(name="system.heartbeat", ignore_result=True, expires=55)
def heartbeat_task() -> None:
    from redis import Redis

    from app.services.system_health import HEARTBEAT_KEY

    client = Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASSWORD or None,
                   socket_connect_timeout=2, socket_timeout=2, db=0)
    try:
        client.set(HEARTBEAT_KEY, str(time.time()), ex=3600)
    finally:
        client.close()
