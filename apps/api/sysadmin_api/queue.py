from __future__ import annotations

from abc import ABC, abstractmethod

from .models import DurableJob
from .service import SysadminService


class JobDispatcher(ABC):
    @abstractmethod
    async def dispatch(self, job: DurableJob) -> None:
        raise NotImplementedError


class InlineJobDispatcher(JobDispatcher):
    def __init__(self, service: SysadminService) -> None:
        self.service = service

    async def dispatch(self, job: DurableJob) -> None:
        if job.status != "queued":
            return
        if job.job_type == "scan":
            await self.service.process_scan(job.id)
        elif job.job_type == "remediation":
            await self.service.process_remediation(job.id)


class CeleryJobDispatcher(JobDispatcher):
    async def dispatch(self, job: DurableJob) -> None:
        if job.status != "queued":
            return
        from .tasks import run_remediation, run_scan

        if job.job_type == "scan":
            run_scan.delay(job.id)
        elif job.job_type == "remediation":
            run_remediation.delay(job.id)
