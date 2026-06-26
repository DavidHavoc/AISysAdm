from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    JSON,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class UserRecord(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="admin")
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CredentialRecord(Base):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    credential_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="ssh_private_key",
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_metadata: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    encrypted_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class HostRecord(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    environment: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScheduleRecord(Base):
    __tablename__ = "host_schedules"
    __table_args__ = (UniqueConstraint("host_id", name="uq_host_schedule_host"),)

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SnapshotRecord(Base):
    __tablename__ = "snapshots"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RollbackSnapshotRecord(Base):
    __tablename__ = "rollback_snapshots"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    remediation_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    external_snapshot_id: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    delete_after: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AgentRunRecord(Base):
    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    contract_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AgentMessageRecord(Base):
    __tablename__ = "agent_messages"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    from_agent: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    to_agent: Mapped[str] = mapped_column(String(64), nullable=False)
    response: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_agent: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RemediationRecord(Base):
    __tablename__ = "remediations"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    approval_state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    execution_state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    plan_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CampaignRecord(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CampaignHostRecord(Base):
    __tablename__ = "campaign_hosts"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "host_id",
            name="uq_campaign_host_campaign_host",
        ),
    )

    id: Mapped[str] = mapped_column(String(196), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    host_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    remediation_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    approval_state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    reboot_approval_state: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        index=True,
    )
    plan_version: Mapped[Optional[int]] = mapped_column(Integer)
    plan_hash: Mapped[Optional[str]] = mapped_column(String(64))
    job_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class JobRecord(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    job_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    host_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(180), unique=True, nullable=False)
    lease_owner: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_failure: Mapped[Optional[dict]] = mapped_column(JSON)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LogEventRecord(Base):
    __tablename__ = "log_events"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    host_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    job_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    remediation_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    agent_run_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    phase_id: Mapped[Optional[str]] = mapped_column(String(160), index=True)
    task_id: Mapped[Optional[str]] = mapped_column(String(160), index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


Index(
    "ix_log_events_timeline",
    LogEventRecord.timestamp,
    LogEventRecord.host_id,
    LogEventRecord.severity,
)


class AlertRecord(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    host_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_id: Mapped[Optional[str]] = mapped_column(String(96), index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def create_session_factory(database_url: str):
    engine_options = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        engine_options["connect_args"] = {"check_same_thread": False}
    engine = create_engine(database_url, **engine_options)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)
