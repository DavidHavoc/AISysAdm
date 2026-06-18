from __future__ import annotations

import asyncio

from celery import Celery

from .config import Settings
from .runtime import get_runtime


settings = Settings()
settings.validate_runtime_requirements()
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
        "purge-expired-logs": {
            "task": "sysadmin.purge_logs",
            "schedule": 86400.0,
        },
    },
)


@celery_app.task(
    name="sysadmin.run_scan",
    autoretry_for=(RuntimeError,),
    retry_backoff=True,
    max_retries=2,
)
def run_scan(job_id: str):
    return asyncio.run(get_runtime().service.process_scan(job_id)).model_dump(mode="json")


@celery_app.task(
    name="sysadmin.run_remediation",
    autoretry_for=(RuntimeError,),
    retry_backoff=True,
    max_retries=1,
)
def run_remediation(job_id: str):
    return asyncio.run(
        get_runtime().service.process_remediation(job_id)
    ).model_dump(mode="json")


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


@celery_app.task(name="sysadmin.purge_logs")
def purge_logs():
    return {"deleted": get_runtime().service.purge_expired_logs()}
