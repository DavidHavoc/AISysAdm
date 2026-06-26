from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, Iterator, List, Optional, Tuple, Type, TypeVar

from sqlalchemy import delete, func, or_, select, text

from .database import (
    AgentMessageRecord,
    AgentRunRecord,
    AlertRecord,
    AuditRecord,
    Base,
    CampaignHostRecord,
    CampaignRecord,
    CredentialRecord,
    FindingRecord,
    HostRecord,
    JobRecord,
    LogEventRecord,
    RemediationRecord,
    RollbackSnapshotRecord,
    ScanRecord,
    ScheduleRecord,
    SessionRecord,
    SnapshotRecord,
    UserRecord,
    create_session_factory,
)
from .models import (
    AgentMessage,
    AgentRun,
    Alert,
    AuditEvent,
    CampaignHostPlan,
    DurableJob,
    Finding,
    Host,
    HostSchedule,
    HostSnapshot,
    JobFailure,
    PatchCampaign,
    Remediation,
    RollbackSnapshot,
    ScanJob,
    SshCredential,
    StructuredLogEvent,
    User,
    UserRole,
)

ModelT = TypeVar("ModelT")


def normalized_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def later_datetime(
    first: Optional[datetime],
    second: Optional[datetime],
) -> Optional[datetime]:
    if first is None:
        return second
    if second is None:
        return first
    return (
        first
        if normalized_datetime(first) >= normalized_datetime(second)
        else second
    )


def lease_is_expired(
    lease_expires_at: Optional[datetime],
    current: datetime,
) -> bool:
    if lease_expires_at is None:
        return True
    return normalized_datetime(lease_expires_at) <= normalized_datetime(current)


def lease_expiration_failure(job: DurableJob, failed_at: datetime) -> JobFailure:
    return JobFailure(
        failed_at=failed_at,
        attempt=job.attempts,
        category="worker_lease_expired",
        message="Worker lease expired before the job completed",
        retryable=job.attempts < job.max_attempts,
    )


def normalized_user_role(value: str) -> str:
    return value.split(".", 1)[1].lower() if value.startswith("UserRole.") else value


def terminalize_exhausted_job(job: DurableJob, failed_at: datetime) -> None:
    message = (
        job.last_failure.message
        if job.last_failure
        else "Job retry attempts were exhausted"
    )
    job.status = "failed"
    job.error = message[:2000]
    job.current_phase = "failed"
    job.completed_at = failed_at
    job.lease_owner = None
    job.lease_expires_at = None
    job.updated_at = failed_at
    if job.last_failure:
        job.last_failure.retryable = False


class Repository:
    @contextmanager
    def transaction(self) -> Iterator[None]:
        raise NotImplementedError

    def list_hosts(self) -> List[Host]:
        raise NotImplementedError

    def save_host(self, host: Host) -> Host:
        raise NotImplementedError

    def get_host(self, host_id: str) -> Optional[Host]:
        raise NotImplementedError

    def save_rollback_snapshot(
        self,
        snapshot: RollbackSnapshot,
    ) -> RollbackSnapshot:
        raise NotImplementedError

    def get_rollback_snapshot(
        self,
        snapshot_id: str,
    ) -> Optional[RollbackSnapshot]:
        raise NotImplementedError

    def list_rollback_snapshots(
        self,
        host_id: Optional[str] = None,
        remediation_id: Optional[str] = None,
    ) -> List[RollbackSnapshot]:
        raise NotImplementedError

    def healthcheck(self) -> bool:
        raise NotImplementedError

    def claim_job(
        self,
        job_id: str,
        lease_owner: str,
        started_at: datetime,
        lease_expires_at: datetime,
    ) -> Optional[DurableJob]:
        raise NotImplementedError

    def heartbeat_job(
        self,
        job_id: str,
        lease_owner: str,
        heartbeat_at: datetime,
        lease_expires_at: datetime,
    ) -> Optional[DurableJob]:
        raise NotImplementedError

    def recover_expired_jobs(
        self,
        recovered_at: datetime,
    ) -> Tuple[List[DurableJob], List[DurableJob]]:
        raise NotImplementedError

    def get_campaign_for_update(self, campaign_id: str) -> Optional[PatchCampaign]:
        raise NotImplementedError

    def get_remediation_for_update(
        self,
        remediation_id: str,
    ) -> Optional[Remediation]:
        raise NotImplementedError

    def cancel_job(
        self,
        job_id: str,
        canceled_at: datetime,
        allowed_statuses: Tuple[str, ...] = ("queued", "scheduled"),
        phase: str = "canceled",
    ) -> Optional[DurableJob]:
        raise NotImplementedError


class InMemoryRepository(Repository):
    def __init__(self) -> None:
        self.hosts: Dict[str, Host] = {}
        self.credentials: Dict[str, Tuple[SshCredential, bytes, bytes]] = {}
        self.schedules: Dict[str, HostSchedule] = {}
        self.snapshots: Dict[str, HostSnapshot] = {}
        self.rollback_snapshots: Dict[str, RollbackSnapshot] = {}
        self.scans: Dict[str, ScanJob] = {}
        self.agent_runs: Dict[str, AgentRun] = {}
        self.agent_messages: Dict[str, AgentMessage] = {}
        self.findings: Dict[str, Finding] = {}
        self.remediations: Dict[str, Remediation] = {}
        self.campaigns: Dict[str, PatchCampaign] = {}
        self.jobs: Dict[str, DurableJob] = {}
        self.logs: Dict[str, StructuredLogEvent] = {}
        self.alerts: Dict[str, Alert] = {}
        self.audits: Dict[str, AuditEvent] = {}
        self.users: Dict[str, Tuple[User, str]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield

    def list_hosts(self) -> List[Host]:
        return list(self.hosts.values())

    def save_host(self, host: Host) -> Host:
        self.hosts[host.id] = host
        return host

    def get_host(self, host_id: str) -> Optional[Host]:
        return self.hosts.get(host_id)

    def healthcheck(self) -> bool:
        return True

    def delete_host(self, host_id: str) -> None:
        self.hosts.pop(host_id, None)

    def save_credential(
        self,
        credential: SshCredential,
        encrypted_key: bytes,
        nonce: bytes,
    ) -> SshCredential:
        self.credentials[credential.id] = (credential, encrypted_key, nonce)
        return credential

    def list_credentials(self) -> List[SshCredential]:
        return [item[0] for item in self.credentials.values()]

    def get_credential_record(
        self,
        credential_id: str,
    ) -> Optional[Tuple[SshCredential, bytes, bytes]]:
        return self.credentials.get(credential_id)

    def delete_credential(self, credential_id: str) -> None:
        self.credentials.pop(credential_id, None)

    def save_schedule(self, schedule: HostSchedule) -> HostSchedule:
        self.schedules[schedule.host_id] = schedule
        return schedule

    def get_schedule(self, host_id: str) -> Optional[HostSchedule]:
        return self.schedules.get(host_id)

    def list_schedules(self) -> List[HostSchedule]:
        return list(self.schedules.values())

    def delete_schedule(self, host_id: str) -> None:
        self.schedules.pop(host_id, None)

    def list_due_schedules(self, now: datetime) -> List[HostSchedule]:
        return [
            item
            for item in self.schedules.values()
            if item.enabled and item.next_run_at and item.next_run_at <= now
        ]

    def save_snapshot(self, snapshot: HostSnapshot) -> HostSnapshot:
        self.snapshots[snapshot.id] = snapshot
        return snapshot

    def get_snapshot(self, snapshot_id: str) -> Optional[HostSnapshot]:
        return self.snapshots.get(snapshot_id)

    def save_rollback_snapshot(
        self,
        snapshot: RollbackSnapshot,
    ) -> RollbackSnapshot:
        self.rollback_snapshots[snapshot.id] = snapshot.model_copy(deep=True)
        return snapshot

    def get_rollback_snapshot(
        self,
        snapshot_id: str,
    ) -> Optional[RollbackSnapshot]:
        snapshot = self.rollback_snapshots.get(snapshot_id)
        return snapshot.model_copy(deep=True) if snapshot else None

    def list_rollback_snapshots(
        self,
        host_id: Optional[str] = None,
        remediation_id: Optional[str] = None,
    ) -> List[RollbackSnapshot]:
        items = [item.model_copy(deep=True) for item in self.rollback_snapshots.values()]
        if host_id:
            items = [item for item in items if item.host_id == host_id]
        if remediation_id:
            items = [
                item for item in items if item.remediation_id == remediation_id
            ]
        return items

    def save_scan(self, scan: ScanJob) -> ScanJob:
        self.scans[scan.id] = scan
        return scan

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        return self.scans.get(scan_id)

    def list_scans(self, host_id: Optional[str] = None) -> List[ScanJob]:
        items = list(self.scans.values())
        return [item for item in items if item.host_id == host_id] if host_id else items

    def save_agent_runs(self, runs: List[AgentRun]) -> List[AgentRun]:
        for item in runs:
            self.agent_runs[item.id] = item
        return runs

    def list_agent_runs(self, scan_id: Optional[str] = None) -> List[AgentRun]:
        items = list(self.agent_runs.values())
        return [item for item in items if item.scan_id == scan_id] if scan_id else items

    def save_agent_messages(self, messages: List[AgentMessage]) -> List[AgentMessage]:
        for item in messages:
            self.agent_messages[item.id] = item
        return messages

    def list_agent_messages(self, scan_id: str) -> List[AgentMessage]:
        return [item for item in self.agent_messages.values() if item.scan_id == scan_id]

    def save_findings(self, findings: List[Finding]) -> List[Finding]:
        for item in findings:
            self.findings[item.id] = item
        return findings

    def list_findings(self, host_id: Optional[str] = None) -> List[Finding]:
        items = list(self.findings.values())
        return [item for item in items if item.host_id == host_id] if host_id else items

    def save_remediation(self, remediation: Remediation) -> Remediation:
        self.remediations[remediation.id] = remediation
        return remediation

    def list_remediations(self) -> List[Remediation]:
        return list(self.remediations.values())

    def get_remediation(self, remediation_id: str) -> Optional[Remediation]:
        return self.remediations.get(remediation_id)

    def get_remediation_for_update(
        self,
        remediation_id: str,
    ) -> Optional[Remediation]:
        with self._lock:
            remediation = self.remediations.get(remediation_id)
            return remediation.model_copy(deep=True) if remediation else None

    def save_campaign(self, campaign: PatchCampaign) -> PatchCampaign:
        self.campaigns[campaign.id] = campaign
        return campaign

    def list_campaigns(self) -> List[PatchCampaign]:
        return list(self.campaigns.values())

    def get_campaign(self, campaign_id: str) -> Optional[PatchCampaign]:
        return self.campaigns.get(campaign_id)

    def get_campaign_for_update(self, campaign_id: str) -> Optional[PatchCampaign]:
        with self._lock:
            campaign = self.campaigns.get(campaign_id)
            return campaign.model_copy(deep=True) if campaign else None

    def save_job(
        self,
        job: DurableJob,
        lease_owner: Optional[str] = None,
    ) -> Optional[DurableJob]:
        with self._lock:
            current = self.jobs.get(job.id)
            if lease_owner is not None:
                if (
                    not current
                    or current.lease_owner != lease_owner
                    or current.status != "running"
                    or lease_is_expired(current.lease_expires_at, job.updated_at)
                ):
                    return None
                if job.status == "running":
                    job.heartbeat_at = later_datetime(
                        job.heartbeat_at,
                        current.heartbeat_at,
                    )
                    job.lease_expires_at = later_datetime(
                        job.lease_expires_at,
                        current.lease_expires_at,
                    )
            self.jobs[job.id] = job.model_copy(deep=True)
        return job

    def claim_job(
        self,
        job_id: str,
        lease_owner: str,
        started_at: datetime,
        lease_expires_at: datetime,
    ) -> Optional[DurableJob]:
        with self._lock:
            stored = self.jobs.get(job_id)
            if not stored:
                return None
            job = stored.model_copy(deep=True)
            expired = job.status == "running" and lease_is_expired(
                job.lease_expires_at,
                started_at,
            )
            if job.status != "queued" and not expired:
                return None
            if job.attempts >= job.max_attempts:
                terminalize_exhausted_job(job, started_at)
                self.jobs[job.id] = job.model_copy(deep=True)
                return None
            if expired:
                job.last_failure = lease_expiration_failure(job, started_at)
            job.status = "running"
            job.started_at = job.started_at or started_at
            job.attempts += 1
            job.lease_owner = lease_owner
            job.lease_expires_at = lease_expires_at
            job.heartbeat_at = started_at
            job.completed_at = None
            job.error = None
            job.updated_at = started_at
            self.jobs[job.id] = job.model_copy(deep=True)
            return job

    def heartbeat_job(
        self,
        job_id: str,
        lease_owner: str,
        heartbeat_at: datetime,
        lease_expires_at: datetime,
    ) -> Optional[DurableJob]:
        with self._lock:
            stored = self.jobs.get(job_id)
            if (
                not stored
                or stored.status != "running"
                or stored.lease_owner != lease_owner
                or lease_is_expired(stored.lease_expires_at, heartbeat_at)
            ):
                return None
            job = stored.model_copy(deep=True)
            job.heartbeat_at = heartbeat_at
            job.lease_expires_at = lease_expires_at
            job.updated_at = heartbeat_at
            self.jobs[job.id] = job.model_copy(deep=True)
            return job

    def recover_expired_jobs(
        self,
        recovered_at: datetime,
    ) -> Tuple[List[DurableJob], List[DurableJob]]:
        recovered: List[DurableJob] = []
        exhausted: List[DurableJob] = []
        with self._lock:
            for stored in list(self.jobs.values()):
                if stored.status != "running" or not lease_is_expired(
                    stored.lease_expires_at,
                    recovered_at,
                ):
                    continue
                job = stored.model_copy(deep=True)
                job.last_failure = lease_expiration_failure(job, recovered_at)
                job.lease_owner = None
                job.lease_expires_at = None
                job.updated_at = recovered_at
                if job.attempts >= job.max_attempts:
                    terminalize_exhausted_job(job, recovered_at)
                    exhausted.append(job)
                else:
                    job.status = "queued"
                    job.current_phase = "retry_scheduled"
                    recovered.append(job)
                self.jobs[job.id] = job.model_copy(deep=True)
        return recovered, exhausted

    def cancel_job(
        self,
        job_id: str,
        canceled_at: datetime,
        allowed_statuses: Tuple[str, ...] = ("queued", "scheduled"),
        phase: str = "canceled",
    ) -> Optional[DurableJob]:
        with self._lock:
            stored = self.jobs.get(job_id)
            if not stored:
                return None
            job = stored.model_copy(deep=True)
            if job.status in allowed_statuses:
                job.status = "canceled"
                job.current_phase = phase
                job.completed_at = canceled_at
                job.updated_at = canceled_at
                job.lease_owner = None
                job.lease_expires_at = None
                self.jobs[job.id] = job.model_copy(deep=True)
            return job

    def get_job(self, job_id: str) -> Optional[DurableJob]:
        job = self.jobs.get(job_id)
        return job.model_copy(deep=True) if job else None

    def get_job_by_idempotency(self, key: str) -> Optional[DurableJob]:
        job = next(
            (item for item in self.jobs.values() if item.idempotency_key == key),
            None,
        )
        return job.model_copy(deep=True) if job else None

    def list_jobs(self) -> List[DurableJob]:
        return [item.model_copy(deep=True) for item in self.jobs.values()]

    def host_has_active_scan(self, host_id: str) -> bool:
        return any(
            item.host_id == host_id
            and item.job_type == "scan"
            and item.status in ("queued", "running")
            for item in self.jobs.values()
        )

    def save_log_events(
        self,
        events: List[StructuredLogEvent],
    ) -> List[StructuredLogEvent]:
        for item in events:
            self.logs[item.id] = item
        return events

    def get_log_event(self, event_id: str) -> Optional[StructuredLogEvent]:
        return self.logs.get(event_id)

    def list_log_events(
        self,
        filters: Dict[str, Any],
        page: int,
        page_size: int,
    ) -> Tuple[List[StructuredLogEvent], int]:
        items = list(self.logs.values())
        for key, value in filters.items():
            if value is not None:
                items = [item for item in items if getattr(item, key) == value]
        items.sort(key=lambda item: item.timestamp, reverse=True)
        start = (page - 1) * page_size
        return items[start : start + page_size], len(items)

    def purge_logs_before(self, cutoff: datetime) -> int:
        ids = [item.id for item in self.logs.values() if item.timestamp < cutoff]
        for event_id in ids:
            self.logs.pop(event_id, None)
        return len(ids)

    def save_alert(self, alert: Alert) -> Alert:
        self.alerts[alert.id] = alert
        return alert

    def list_alerts(self) -> List[Alert]:
        return list(self.alerts.values())

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self.alerts.get(alert_id)

    def save_audit(self, event: AuditEvent) -> AuditEvent:
        self.audits[event.id] = event
        return event

    def list_audits(self) -> List[AuditEvent]:
        return list(self.audits.values())

    def save_user(self, user: User, password_hash: str) -> User:
        self.users[user.id] = (user, password_hash)
        return user

    def get_user_by_username(self, username: str) -> Optional[Tuple[User, str]]:
        return next(
            (item for item in self.users.values() if item[0].username == username),
            None,
        )

    def get_user(self, user_id: str) -> Optional[User]:
        item = self.users.get(user_id)
        return item[0] if item else None

    def save_session(
        self,
        session_id: str,
        user_id: str,
        token_hash: str,
        csrf_hash: str,
        expires_at: datetime,
        created_at: datetime,
    ) -> None:
        self.sessions[token_hash] = {
            "id": session_id,
            "user_id": user_id,
            "csrf_hash": csrf_hash,
            "expires_at": expires_at,
            "created_at": created_at,
        }

    def get_session(self, token_hash: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(token_hash)

    def delete_session(self, token_hash: str) -> None:
        self.sessions.pop(token_hash, None)


class SqlRepository(Repository):
    def __init__(self, database_url: str, create_schema: bool = False) -> None:
        self.engine, self.Session = create_session_factory(database_url)
        self._active_session: ContextVar[Any] = ContextVar(
            "sql_repository_active_session",
            default=None,
        )
        if create_schema:
            Base.metadata.create_all(self.engine)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        active = self._active_session.get()
        if active is not None:
            yield
            return
        with self.Session.begin() as session:
            token = self._active_session.set(session)
            try:
                yield
            finally:
                self._active_session.reset(token)

    @contextmanager
    def _session_scope(self, write: bool = False) -> Iterator[Any]:
        active = self._active_session.get()
        if active is not None:
            yield active
            return
        manager = self.Session.begin if write else self.Session
        with manager() as session:
            token = self._active_session.set(session)
            try:
                yield session
            finally:
                self._active_session.reset(token)

    @staticmethod
    def _payload(item) -> dict:
        return item.model_dump(mode="json", by_alias=False)

    @staticmethod
    def _job_from_row(row: JobRecord) -> DurableJob:
        payload = dict(row.payload)
        payload.update(
            {
                "id": row.id,
                "job_type": row.job_type,
                "status": row.status,
                "host_id": row.host_id,
                "idempotency_key": row.idempotency_key,
                "lease_owner": row.lease_owner,
                "lease_expires_at": row.lease_expires_at,
                "heartbeat_at": row.heartbeat_at,
                "attempts": row.attempts,
                "last_failure": row.last_failure,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )
        return DurableJob.model_validate(payload)

    def list_hosts(self) -> List[Host]:
        return self._list_payload(HostRecord, Host)

    def healthcheck(self) -> bool:
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True

    def save_host(self, host: Host) -> Host:
        with self._session_scope(write=True) as session:
            record = session.get(HostRecord, host.id)
            values = {
                "name": host.name,
                "address": host.address,
                "environment": host.environment,
                "payload": self._payload(host),
                "created_at": host.created_at,
                "updated_at": host.updated_at,
            }
            if record:
                for key, value in values.items():
                    setattr(record, key, value)
            else:
                session.add(HostRecord(id=host.id, **values))
        return host

    def get_host(self, host_id: str) -> Optional[Host]:
        return self._get_payload(HostRecord, Host, host_id)

    def delete_host(self, host_id: str) -> None:
        with self._session_scope(write=True) as session:
            session.execute(delete(HostRecord).where(HostRecord.id == host_id))

    def save_credential(
        self,
        credential: SshCredential,
        encrypted_key: bytes,
        nonce: bytes,
    ) -> SshCredential:
        with self._session_scope(write=True) as session:
            record = session.get(CredentialRecord, credential.id)
            values = {
                "name": credential.name,
                "credential_type": (
                    credential.credential_type.value
                    if hasattr(credential.credential_type, "value")
                    else str(credential.credential_type)
                ),
                "fingerprint": credential.fingerprint,
                "credential_metadata": credential.metadata,
                "encrypted_key": encrypted_key,
                "nonce": nonce,
                "created_at": credential.created_at,
                "last_used_at": credential.last_used_at,
            }
            if record:
                for key, value in values.items():
                    setattr(record, key, value)
            else:
                session.add(CredentialRecord(id=credential.id, **values))
        return credential

    def list_credentials(self) -> List[SshCredential]:
        with self._session_scope() as session:
            rows = session.scalars(select(CredentialRecord)).all()
        return [
            SshCredential(
                id=row.id,
                name=row.name,
                credential_type=getattr(
                    row,
                    "credential_type",
                    "ssh_private_key",
                ),
                fingerprint=row.fingerprint,
                metadata=getattr(row, "credential_metadata", {}) or {},
                created_at=row.created_at,
                last_used_at=row.last_used_at,
            )
            for row in rows
        ]

    def get_credential_record(
        self,
        credential_id: str,
    ) -> Optional[Tuple[SshCredential, bytes, bytes]]:
        with self._session_scope() as session:
            row = session.get(CredentialRecord, credential_id)
            if not row:
                return None
            return (
                SshCredential(
                    id=row.id,
                    name=row.name,
                    credential_type=getattr(
                        row,
                        "credential_type",
                        "ssh_private_key",
                    ),
                    fingerprint=row.fingerprint,
                    metadata=getattr(row, "credential_metadata", {}) or {},
                    created_at=row.created_at,
                    last_used_at=row.last_used_at,
                ),
                row.encrypted_key,
                row.nonce,
            )

    def delete_credential(self, credential_id: str) -> None:
        with self._session_scope(write=True) as session:
            session.execute(
                delete(CredentialRecord).where(CredentialRecord.id == credential_id)
            )

    def save_schedule(self, schedule: HostSchedule) -> HostSchedule:
        return self._upsert_payload(
            ScheduleRecord,
            schedule,
            {
                "host_id": schedule.host_id,
                "enabled": schedule.enabled,
                "next_run_at": schedule.next_run_at,
                "created_at": schedule.created_at,
                "updated_at": schedule.updated_at,
            },
        )

    def get_schedule(self, host_id: str) -> Optional[HostSchedule]:
        with self._session_scope() as session:
            row = session.scalar(
                select(ScheduleRecord).where(ScheduleRecord.host_id == host_id)
            )
        return HostSchedule.model_validate(row.payload) if row else None

    def list_schedules(self) -> List[HostSchedule]:
        return self._list_payload(ScheduleRecord, HostSchedule)

    def delete_schedule(self, host_id: str) -> None:
        with self._session_scope(write=True) as session:
            session.execute(
                delete(ScheduleRecord).where(ScheduleRecord.host_id == host_id)
            )

    def list_due_schedules(self, now: datetime) -> List[HostSchedule]:
        with self._session_scope() as session:
            rows = session.scalars(
                select(ScheduleRecord).where(
                    ScheduleRecord.enabled.is_(True),
                    ScheduleRecord.next_run_at <= now,
                )
            ).all()
        return [HostSchedule.model_validate(row.payload) for row in rows]

    def save_snapshot(self, snapshot: HostSnapshot) -> HostSnapshot:
        return self._upsert_payload(
            SnapshotRecord,
            snapshot,
            {
                "host_id": snapshot.host_id,
                "snapshot_hash": snapshot.snapshot_hash,
                "collected_at": snapshot.collected_at,
            },
        )

    def get_snapshot(self, snapshot_id: str) -> Optional[HostSnapshot]:
        return self._get_payload(SnapshotRecord, HostSnapshot, snapshot_id)

    def save_rollback_snapshot(
        self,
        snapshot: RollbackSnapshot,
    ) -> RollbackSnapshot:
        return self._upsert_payload(
            RollbackSnapshotRecord,
            snapshot,
            {
                "host_id": snapshot.host_id,
                "remediation_id": snapshot.remediation_id,
                "provider": (
                    snapshot.provider.value
                    if hasattr(snapshot.provider, "value")
                    else str(snapshot.provider)
                ),
                "state": (
                    snapshot.state.value
                    if hasattr(snapshot.state, "value")
                    else str(snapshot.state)
                ),
                "external_snapshot_id": snapshot.external_snapshot_id,
                "delete_after": snapshot.delete_after,
                "created_at": snapshot.created_at,
                "updated_at": snapshot.updated_at,
            },
        )

    def get_rollback_snapshot(
        self,
        snapshot_id: str,
    ) -> Optional[RollbackSnapshot]:
        return self._get_payload(
            RollbackSnapshotRecord,
            RollbackSnapshot,
            snapshot_id,
        )

    def list_rollback_snapshots(
        self,
        host_id: Optional[str] = None,
        remediation_id: Optional[str] = None,
    ) -> List[RollbackSnapshot]:
        statement = select(RollbackSnapshotRecord)
        if host_id:
            statement = statement.where(RollbackSnapshotRecord.host_id == host_id)
        if remediation_id:
            statement = statement.where(
                RollbackSnapshotRecord.remediation_id == remediation_id
            )
        with self._session_scope() as session:
            rows = session.scalars(statement).all()
        return [RollbackSnapshot.model_validate(row.payload) for row in rows]

    def save_scan(self, scan: ScanJob) -> ScanJob:
        return self._upsert_payload(
            ScanRecord,
            scan,
            {
                "host_id": scan.host_id,
                "status": scan.status,
                "trigger": scan.trigger,
                "created_at": scan.created_at,
                "updated_at": scan.updated_at,
            },
        )

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        return self._get_payload(ScanRecord, ScanJob, scan_id)

    def list_scans(self, host_id: Optional[str] = None) -> List[ScanJob]:
        statement = select(ScanRecord)
        if host_id:
            statement = statement.where(ScanRecord.host_id == host_id)
        with self._session_scope() as session:
            rows = session.scalars(statement).all()
        return [ScanJob.model_validate(row.payload) for row in rows]

    def save_agent_runs(self, runs: List[AgentRun]) -> List[AgentRun]:
        for item in runs:
            self._upsert_payload(
                AgentRunRecord,
                item,
                {
                    "scan_id": item.scan_id,
                    "agent_name": str(item.agent.name),
                    "provider": item.agent.provider,
                    "model": item.agent.model,
                    "contract_hash": item.agent.contract_hash,
                    "input_hash": item.input_hash,
                    "created_at": item.created_at,
                },
            )
        return runs

    def list_agent_runs(self, scan_id: Optional[str] = None) -> List[AgentRun]:
        statement = select(AgentRunRecord)
        if scan_id:
            statement = statement.where(AgentRunRecord.scan_id == scan_id)
        with self._session_scope() as session:
            rows = session.scalars(statement).all()
        return [AgentRun.model_validate(row.payload) for row in rows]

    def save_agent_messages(self, messages: List[AgentMessage]) -> List[AgentMessage]:
        for item in messages:
            self._upsert_payload(
                AgentMessageRecord,
                item,
                {
                    "scan_id": item.scan_id,
                    "from_agent": str(item.from_agent),
                    "to_agent": str(item.to_agent),
                    "response": item.response,
                    "created_at": item.created_at,
                },
            )
        return messages

    def list_agent_messages(self, scan_id: str) -> List[AgentMessage]:
        with self._session_scope() as session:
            rows = session.scalars(
                select(AgentMessageRecord).where(
                    AgentMessageRecord.scan_id == scan_id
                )
            ).all()
        return [AgentMessage.model_validate(row.payload) for row in rows]

    def save_findings(self, findings: List[Finding]) -> List[Finding]:
        for item in findings:
            self._upsert_payload(
                FindingRecord,
                item,
                {
                    "host_id": item.host_id,
                    "scan_id": item.scan_id or "",
                    "severity": str(item.severity),
                    "source_agent": str(item.source_agent),
                    "created_at": item.created_at,
                },
            )
        return findings

    def list_findings(self, host_id: Optional[str] = None) -> List[Finding]:
        statement = select(FindingRecord)
        if host_id:
            statement = statement.where(FindingRecord.host_id == host_id)
        with self._session_scope() as session:
            rows = session.scalars(statement).all()
        return [Finding.model_validate(row.payload) for row in rows]

    def save_remediation(self, remediation: Remediation) -> Remediation:
        return self._upsert_payload(
            RemediationRecord,
            remediation,
            {
                "host_id": remediation.host_id,
                "scan_id": remediation.scan_id,
                "approval_state": remediation.approval_state,
                "execution_state": remediation.execution_state,
                "plan_hash": remediation.plan_hash,
                "created_at": remediation.created_at,
                "updated_at": remediation.updated_at,
            },
        )

    def list_remediations(self) -> List[Remediation]:
        return self._list_payload(RemediationRecord, Remediation)

    def get_remediation(self, remediation_id: str) -> Optional[Remediation]:
        return self._get_payload(RemediationRecord, Remediation, remediation_id)

    def get_remediation_for_update(
        self,
        remediation_id: str,
    ) -> Optional[Remediation]:
        with self._session_scope(write=True) as session:
            row = session.scalar(
                select(RemediationRecord)
                .where(RemediationRecord.id == remediation_id)
                .with_for_update()
            )
        return Remediation.model_validate(row.payload) if row else None

    def save_campaign(self, campaign: PatchCampaign) -> PatchCampaign:
        with self._session_scope(write=True) as session:
            record = session.get(CampaignRecord, campaign.id)
            values = {
                "status": (
                    campaign.status.value
                    if hasattr(campaign.status, "value")
                    else str(campaign.status)
                ),
                "payload": self._payload(campaign),
                "created_at": campaign.created_at,
                "updated_at": campaign.updated_at,
            }
            if record:
                for key, value in values.items():
                    setattr(record, key, value)
            else:
                session.add(CampaignRecord(id=campaign.id, **values))
            for host_plan in campaign.hosts:
                record_id = host_plan.id
                host_record = session.get(CampaignHostRecord, record_id)
                host_values = {
                    "campaign_id": campaign.id,
                    "host_id": host_plan.host_id,
                    "remediation_id": host_plan.remediation_id,
                    "state": (
                        host_plan.state.value
                        if hasattr(host_plan.state, "value")
                        else str(host_plan.state)
                    ),
                    "approval_state": host_plan.approval_state,
                    "reboot_approval_state": host_plan.reboot_approval_state,
                    "plan_version": host_plan.plan_version,
                    "plan_hash": host_plan.plan_hash,
                    "job_id": host_plan.job_id,
                    "payload": self._payload(host_plan),
                    "created_at": host_plan.created_at,
                    "updated_at": host_plan.updated_at,
                }
                if host_record:
                    for key, value in host_values.items():
                        setattr(host_record, key, value)
                else:
                    session.add(CampaignHostRecord(id=record_id, **host_values))
        return campaign

    def list_campaigns(self) -> List[PatchCampaign]:
        return [
            self._campaign_with_hosts(item)
            for item in self._list_payload(CampaignRecord, PatchCampaign)
        ]

    def get_campaign(self, campaign_id: str) -> Optional[PatchCampaign]:
        campaign = self._get_payload(CampaignRecord, PatchCampaign, campaign_id)
        return self._campaign_with_hosts(campaign) if campaign else None

    def get_campaign_for_update(self, campaign_id: str) -> Optional[PatchCampaign]:
        with self._session_scope(write=True) as session:
            row = session.scalar(
                select(CampaignRecord)
                .where(CampaignRecord.id == campaign_id)
                .with_for_update()
            )
            if not row:
                return None
            campaign = PatchCampaign.model_validate(row.payload)
            rows = session.scalars(
                select(CampaignHostRecord)
                .where(CampaignHostRecord.campaign_id == campaign.id)
                .with_for_update()
            ).all()
        if rows:
            campaign.hosts = [
                CampaignHostPlan.model_validate(host_row.payload)
                for host_row in rows
            ]
            campaign.hosts.sort(key=lambda item: item.hostname)
        return campaign

    def _campaign_with_hosts(self, campaign: PatchCampaign) -> PatchCampaign:
        with self._session_scope() as session:
            rows = session.scalars(
                select(CampaignHostRecord).where(
                    CampaignHostRecord.campaign_id == campaign.id
                )
            ).all()
        if rows:
            campaign.hosts = [
                CampaignHostPlan.model_validate(row.payload)
                for row in rows
            ]
            campaign.hosts.sort(key=lambda item: item.hostname)
        return campaign

    @staticmethod
    def _job_values(job: DurableJob) -> Dict[str, Any]:
        return {
            "job_type": job.job_type,
            "status": job.status,
            "host_id": job.host_id,
            "idempotency_key": job.idempotency_key,
            "lease_owner": job.lease_owner,
            "lease_expires_at": job.lease_expires_at,
            "heartbeat_at": job.heartbeat_at,
            "attempts": job.attempts,
            "last_failure": (
                job.last_failure.model_dump(mode="json")
                if job.last_failure
                else None
            ),
            "payload": SqlRepository._payload(job),
            "created_at": job.created_at,
            "updated_at": job.updated_at,
        }

    def save_job(
        self,
        job: DurableJob,
        lease_owner: Optional[str] = None,
    ) -> Optional[DurableJob]:
        with self._session_scope(write=True) as session:
            row = session.scalar(
                select(JobRecord)
                .where(JobRecord.id == job.id)
                .with_for_update()
            )
            if lease_owner is not None:
                if (
                    not row
                    or row.lease_owner != lease_owner
                    or row.status != "running"
                    or lease_is_expired(row.lease_expires_at, job.updated_at)
                ):
                    return None
                if job.status == "running":
                    job.heartbeat_at = later_datetime(
                        job.heartbeat_at,
                        row.heartbeat_at,
                    )
                    job.lease_expires_at = later_datetime(
                        job.lease_expires_at,
                        row.lease_expires_at,
                    )
            values = self._job_values(job)
            if row:
                for key, value in values.items():
                    setattr(row, key, value)
            else:
                session.add(JobRecord(id=job.id, **values))
        return job

    def claim_job(
        self,
        job_id: str,
        lease_owner: str,
        started_at: datetime,
        lease_expires_at: datetime,
    ) -> Optional[DurableJob]:
        with self._session_scope(write=True) as session:
            row = session.scalar(
                select(JobRecord)
                .where(JobRecord.id == job_id)
                .with_for_update()
            )
            if not row:
                return None
            job = self._job_from_row(row)
            expired = row.status == "running" and lease_is_expired(
                row.lease_expires_at,
                started_at,
            )
            if row.status != "queued" and not expired:
                return None
            if row.attempts >= job.max_attempts:
                terminalize_exhausted_job(job, started_at)
                for key, value in self._job_values(job).items():
                    setattr(row, key, value)
                return None
            if expired:
                job.last_failure = lease_expiration_failure(job, started_at)
            job.status = "running"
            job.started_at = job.started_at or started_at
            job.attempts += 1
            job.lease_owner = lease_owner
            job.lease_expires_at = lease_expires_at
            job.heartbeat_at = started_at
            job.completed_at = None
            job.error = None
            job.updated_at = started_at
            for key, value in self._job_values(job).items():
                setattr(row, key, value)
            return job

    def heartbeat_job(
        self,
        job_id: str,
        lease_owner: str,
        heartbeat_at: datetime,
        lease_expires_at: datetime,
    ) -> Optional[DurableJob]:
        with self._session_scope(write=True) as session:
            row = session.scalar(
                select(JobRecord)
                .where(JobRecord.id == job_id)
                .with_for_update()
            )
            if (
                not row
                or row.status != "running"
                or row.lease_owner != lease_owner
                or lease_is_expired(row.lease_expires_at, heartbeat_at)
            ):
                return None
            job = self._job_from_row(row)
            job.heartbeat_at = heartbeat_at
            job.lease_expires_at = lease_expires_at
            job.updated_at = heartbeat_at
            for key, value in self._job_values(job).items():
                setattr(row, key, value)
            return job

    def recover_expired_jobs(
        self,
        recovered_at: datetime,
    ) -> Tuple[List[DurableJob], List[DurableJob]]:
        recovered: List[DurableJob] = []
        exhausted: List[DurableJob] = []
        with self._session_scope(write=True) as session:
            rows = session.scalars(
                select(JobRecord)
                .where(
                    JobRecord.status == "running",
                    or_(
                        JobRecord.lease_expires_at.is_(None),
                        JobRecord.lease_expires_at <= recovered_at,
                    ),
                )
                .with_for_update(skip_locked=True)
            ).all()
            for row in rows:
                job = self._job_from_row(row)
                job.last_failure = lease_expiration_failure(job, recovered_at)
                job.lease_owner = None
                job.lease_expires_at = None
                job.updated_at = recovered_at
                if job.attempts >= job.max_attempts:
                    terminalize_exhausted_job(job, recovered_at)
                    exhausted.append(job)
                else:
                    job.status = "queued"
                    job.current_phase = "retry_scheduled"
                    recovered.append(job)
                for key, value in self._job_values(job).items():
                    setattr(row, key, value)
        return recovered, exhausted

    def cancel_job(
        self,
        job_id: str,
        canceled_at: datetime,
        allowed_statuses: Tuple[str, ...] = ("queued", "scheduled"),
        phase: str = "canceled",
    ) -> Optional[DurableJob]:
        with self._session_scope(write=True) as session:
            row = session.scalar(
                select(JobRecord)
                .where(JobRecord.id == job_id)
                .with_for_update()
            )
            if not row:
                return None
            job = self._job_from_row(row)
            if row.status in allowed_statuses:
                job.status = "canceled"
                job.current_phase = phase
                job.completed_at = canceled_at
                job.updated_at = canceled_at
                job.lease_owner = None
                job.lease_expires_at = None
                for key, value in self._job_values(job).items():
                    setattr(row, key, value)
            return job

    def get_job(self, job_id: str) -> Optional[DurableJob]:
        with self._session_scope() as session:
            row = session.get(JobRecord, job_id)
        return self._job_from_row(row) if row else None

    def get_job_by_idempotency(self, key: str) -> Optional[DurableJob]:
        with self._session_scope() as session:
            row = session.scalar(
                select(JobRecord).where(JobRecord.idempotency_key == key)
            )
        return self._job_from_row(row) if row else None

    def list_jobs(self) -> List[DurableJob]:
        with self._session_scope() as session:
            rows = session.scalars(select(JobRecord)).all()
        return [self._job_from_row(row) for row in rows]

    def host_has_active_scan(self, host_id: str) -> bool:
        with self._session_scope() as session:
            count = session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(
                    JobRecord.host_id == host_id,
                    JobRecord.job_type == "scan",
                    JobRecord.status.in_(["queued", "running"]),
                )
            )
        return bool(count)

    def save_log_events(
        self,
        events: List[StructuredLogEvent],
    ) -> List[StructuredLogEvent]:
        for item in events:
            self._upsert_payload(
                LogEventRecord,
                item,
                {
                    "timestamp": item.timestamp,
                    "host_id": item.host_id,
                    "job_id": item.job_id,
                    "scan_id": item.scan_id,
                    "remediation_id": item.remediation_id,
                    "agent_run_id": item.agent_run_id,
                    "severity": str(item.severity),
                    "source": item.source,
                    "phase_id": item.phase_id,
                    "task_id": item.task_id,
                },
            )
        return events

    def get_log_event(self, event_id: str) -> Optional[StructuredLogEvent]:
        return self._get_payload(LogEventRecord, StructuredLogEvent, event_id)

    def list_log_events(
        self,
        filters: Dict[str, Any],
        page: int,
        page_size: int,
    ) -> Tuple[List[StructuredLogEvent], int]:
        statement = select(LogEventRecord)
        count_statement = select(func.count()).select_from(LogEventRecord)
        column_map = {
            "host_id": LogEventRecord.host_id,
            "job_id": LogEventRecord.job_id,
            "scan_id": LogEventRecord.scan_id,
            "remediation_id": LogEventRecord.remediation_id,
            "agent_run_id": LogEventRecord.agent_run_id,
            "severity": LogEventRecord.severity,
            "source": LogEventRecord.source,
            "phase_id": LogEventRecord.phase_id,
            "task_id": LogEventRecord.task_id,
        }
        for key, value in filters.items():
            if value is not None and key in column_map:
                statement = statement.where(column_map[key] == value)
                count_statement = count_statement.where(column_map[key] == value)
        statement = (
            statement.order_by(LogEventRecord.timestamp.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        with self._session_scope() as session:
            rows = session.scalars(statement).all()
            total = int(session.scalar(count_statement) or 0)
        return [StructuredLogEvent.model_validate(row.payload) for row in rows], total

    def purge_logs_before(self, cutoff: datetime) -> int:
        with self._session_scope(write=True) as session:
            result = session.execute(
                delete(LogEventRecord).where(LogEventRecord.timestamp < cutoff)
            )
        return int(result.rowcount or 0)

    def save_alert(self, alert: Alert) -> Alert:
        return self._upsert_payload(
            AlertRecord,
            alert,
            {
                "severity": str(alert.severity),
                "acknowledged": alert.acknowledged,
                "host_id": alert.host_id,
                "created_at": alert.created_at,
            },
        )

    def list_alerts(self) -> List[Alert]:
        return self._list_payload(AlertRecord, Alert)

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self._get_payload(AlertRecord, Alert, alert_id)

    def save_audit(self, event: AuditEvent) -> AuditEvent:
        return self._upsert_payload(
            AuditRecord,
            event,
            {
                "actor": event.actor,
                "action": event.action,
                "target_type": event.target_type,
                "target_id": event.target_id,
                "created_at": event.created_at,
            },
        )

    def list_audits(self) -> List[AuditEvent]:
        return self._list_payload(AuditRecord, AuditEvent)

    def save_user(self, user: User, password_hash: str) -> User:
        with self._session_scope(write=True) as session:
            record = session.get(UserRecord, user.id)
            values = {
                "username": user.username,
                "role": (
                    user.role.value
                    if isinstance(user.role, UserRole)
                    else normalized_user_role(str(user.role))
                ),
                "password_hash": password_hash,
                "created_at": user.created_at,
            }
            if record:
                for key, value in values.items():
                    setattr(record, key, value)
            else:
                session.add(UserRecord(id=user.id, **values))
        return user

    def get_user_by_username(self, username: str) -> Optional[Tuple[User, str]]:
        with self._session_scope() as session:
            row = session.scalar(
                select(UserRecord).where(UserRecord.username == username)
            )
        if not row:
            return None
        return (
            User(
                id=row.id,
                username=row.username,
                role=normalized_user_role(row.role),
                created_at=row.created_at,
            ),
            row.password_hash,
        )

    def get_user(self, user_id: str) -> Optional[User]:
        with self._session_scope() as session:
            row = session.get(UserRecord, user_id)
        return (
            User(
                id=row.id,
                username=row.username,
                role=normalized_user_role(row.role),
                created_at=row.created_at,
            )
            if row
            else None
        )

    def save_session(
        self,
        session_id: str,
        user_id: str,
        token_hash: str,
        csrf_hash: str,
        expires_at: datetime,
        created_at: datetime,
    ) -> None:
        with self._session_scope(write=True) as session:
            session.add(
                SessionRecord(
                    id=session_id,
                    user_id=user_id,
                    token_hash=token_hash,
                    csrf_hash=csrf_hash,
                    expires_at=expires_at,
                    created_at=created_at,
                )
            )

    def get_session(self, token_hash: str) -> Optional[Dict[str, Any]]:
        with self._session_scope() as session:
            row = session.scalar(
                select(SessionRecord).where(SessionRecord.token_hash == token_hash)
            )
        if not row:
            return None
        return {
            "id": row.id,
            "user_id": row.user_id,
            "csrf_hash": row.csrf_hash,
            "expires_at": row.expires_at,
            "created_at": row.created_at,
        }

    def delete_session(self, token_hash: str) -> None:
        with self._session_scope(write=True) as session:
            session.execute(
                delete(SessionRecord).where(SessionRecord.token_hash == token_hash)
            )

    def _get_payload(
        self,
        record_type,
        model_type: Type[ModelT],
        item_id: str,
    ) -> Optional[ModelT]:
        with self._session_scope() as session:
            row = session.get(record_type, item_id)
        return model_type.model_validate(row.payload) if row else None

    def _list_payload(self, record_type, model_type: Type[ModelT]) -> List[ModelT]:
        with self._session_scope() as session:
            rows = session.scalars(select(record_type)).all()
        return [model_type.model_validate(row.payload) for row in rows]

    def _upsert_payload(self, record_type, item: ModelT, values: Dict[str, Any]) -> ModelT:
        with self._session_scope(write=True) as session:
            row = session.get(record_type, item.id)
            payload = self._payload(item)
            if row:
                row.payload = payload
                for key, value in values.items():
                    setattr(row, key, value)
            else:
                session.add(record_type(id=item.id, payload=payload, **values))
        return item
