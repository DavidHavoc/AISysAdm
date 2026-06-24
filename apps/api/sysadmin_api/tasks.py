from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from celery import Celery
from celery.signals import heartbeat_sent, worker_ready
from redis import Redis

from .config import BEAT_HEALTH_KEY, WORKER_HEALTH_KEY, Settings
from .redaction import sanitize_celery_payload
from .runtime import get_runtime


settings = Settings()
settings.validate_runtime_requirements()
health_redis = (
    Redis.from_url(settings.redis_url, decode_responses=True)
    if settings.redis_url
    else None
)
celery_app = Celery(
    "ai_sysadm",
    broker=settings.redis_url or "memory://",
    backend=settings.redis_url or "cache+memory://",
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    timezone="UTC",
    beat_schedule={
        "dispatch-host-schedules": {
            "task": "sysadmin.dispatch_schedules",
            "schedule": 60.0,
        },
        "release-maintenance-jobs": {
            "task": "sysadmin.release_maintenance_jobs",
            "schedule": 60.0,
        },
        "recover-expired-jobs": {
            "task": "sysadmin.recover_expired_jobs",
            "schedule": 30.0,
        },
        "operational-health-heartbeat": {
            "task": "sysadmin.operational_health_heartbeat",
            "schedule": 30.0,
        },
        "purge-expired-logs": {
            "task": "sysadmin.purge_logs",
            "schedule": 86400.0,
        },
    },
)


def _health_client():
    return health_redis


def _record_health(key: str) -> None:
    client = _health_client()
    if not client:
        return
    try:
        client.set(
            key,
            datetime.now(timezone.utc).isoformat(),
            ex=settings.operational_health_ttl_seconds,
        )
    except Exception:
        return


def _worker_id(task) -> str:
    hostname = getattr(task.request, "hostname", None) or "worker"
    task_id = getattr(task.request, "id", None) or "delivery"
    return "%s:%s:%s" % (hostname, task_id, uuid4().hex)


def _schedule_retry(task, job) -> None:
    if job.status != "queued" or job.current_phase != "retry_scheduled":
        return
    countdown = min(60, 2 ** max(0, job.attempts - 1))
    task.apply_async(args=[job.id], countdown=countdown)


@worker_ready.connect
def record_worker_ready(**kwargs):
    _record_health(WORKER_HEALTH_KEY)


@heartbeat_sent.connect
def record_worker_heartbeat(**kwargs):
    _record_health(WORKER_HEALTH_KEY)


@celery_app.task(
    name="sysadmin.run_scan",
    bind=True,
)
def run_scan(self, job_id: str):
    _record_health(WORKER_HEALTH_KEY)
    job = asyncio.run(
        get_runtime().service.process_scan(job_id, _worker_id(self))
    )
    _schedule_retry(run_scan, job)
    return sanitize_celery_payload(job.model_dump(mode="json"))


@celery_app.task(
    name="sysadmin.run_remediation",
    bind=True,
)
def run_remediation(self, job_id: str):
    _record_health(WORKER_HEALTH_KEY)
    job = asyncio.run(
        get_runtime().service.process_remediation(job_id, _worker_id(self))
    )
    _schedule_retry(run_remediation, job)
    return sanitize_celery_payload(job.model_dump(mode="json"))


@celery_app.task(name="sysadmin.dispatch_schedules")
def dispatch_schedules():
    jobs = get_runtime().service.create_due_scan_jobs()
    for job in jobs:
        run_scan.delay(job.id)
    return {"queued": len(jobs)}


@celery_app.task(name="sysadmin.release_maintenance_jobs")
def release_maintenance_jobs():
    jobs = get_runtime().service.release_scheduled_remediation_jobs()
    for job in jobs:
        run_remediation.delay(job.id)
    return {"queued": len(jobs)}


@celery_app.task(name="sysadmin.recover_expired_jobs")
def recover_expired_jobs():
    jobs = get_runtime().service.recover_expired_jobs()
    for job in jobs:
        if job.job_type == "scan":
            run_scan.delay(job.id)
        elif job.job_type == "remediation":
            run_remediation.delay(job.id)
    return {"queued": len(jobs)}


@celery_app.task(name="sysadmin.operational_health_heartbeat")
def operational_health_heartbeat():
    _record_health(WORKER_HEALTH_KEY)
    _record_health(BEAT_HEALTH_KEY)
    return {"ok": True}


@celery_app.task(name="sysadmin.purge_logs")
def purge_logs():
    return {"deleted": get_runtime().service.purge_expired_logs()}
