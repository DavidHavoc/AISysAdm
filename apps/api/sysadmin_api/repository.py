from __future__ import annotations

from abc import ABC, abstractmethod
from threading import RLock
from typing import Dict, List, Optional, Type, TypeVar

from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, create_engine, delete, select
from sqlalchemy.engine import Engine

from .models import Finding, Host, PatchCampaign, Remediation, ScanJob, utc_now

ModelT = TypeVar("ModelT", Host, Finding, Remediation, ScanJob, PatchCampaign)


class Repository(ABC):
    @abstractmethod
    def list_hosts(self) -> List[Host]:
        raise NotImplementedError

    @abstractmethod
    def save_host(self, host: Host) -> Host:
        raise NotImplementedError

    @abstractmethod
    def get_host(self, host_id: str) -> Optional[Host]:
        raise NotImplementedError

    @abstractmethod
    def save_scan(self, scan: ScanJob) -> ScanJob:
        raise NotImplementedError

    @abstractmethod
    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        raise NotImplementedError

    @abstractmethod
    def save_findings(self, findings: List[Finding]) -> List[Finding]:
        raise NotImplementedError

    @abstractmethod
    def list_findings(self, host_id: str) -> List[Finding]:
        raise NotImplementedError

    @abstractmethod
    def save_remediation(self, remediation: Remediation) -> Remediation:
        raise NotImplementedError

    @abstractmethod
    def list_remediations(self) -> List[Remediation]:
        raise NotImplementedError

    @abstractmethod
    def get_remediation(self, remediation_id: str) -> Optional[Remediation]:
        raise NotImplementedError

    @abstractmethod
    def save_campaign(self, campaign: PatchCampaign) -> PatchCampaign:
        raise NotImplementedError

    @abstractmethod
    def list_campaigns(self) -> List[PatchCampaign]:
        raise NotImplementedError

    @abstractmethod
    def get_campaign(self, campaign_id: str) -> Optional[PatchCampaign]:
        raise NotImplementedError


class InMemoryRepository(Repository):
    def __init__(self) -> None:
        self._hosts: Dict[str, Host] = {}
        self._scans: Dict[str, ScanJob] = {}
        self._findings: Dict[str, Finding] = {}
        self._remediations: Dict[str, Remediation] = {}
        self._campaigns: Dict[str, PatchCampaign] = {}
        self._lock = RLock()

    def list_hosts(self) -> List[Host]:
        return list(self._hosts.values())

    def save_host(self, host: Host) -> Host:
        with self._lock:
            self._hosts[host.id] = host
        return host

    def get_host(self, host_id: str) -> Optional[Host]:
        return self._hosts.get(host_id)

    def save_scan(self, scan: ScanJob) -> ScanJob:
        with self._lock:
            self._scans[scan.id] = scan
        return scan

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        return self._scans.get(scan_id)

    def save_findings(self, findings: List[Finding]) -> List[Finding]:
        with self._lock:
            for finding in findings:
                self._findings[finding.id] = finding
        return findings

    def list_findings(self, host_id: str) -> List[Finding]:
        return [item for item in self._findings.values() if item.host_id == host_id]

    def save_remediation(self, remediation: Remediation) -> Remediation:
        with self._lock:
            self._remediations[remediation.id] = remediation
        return remediation

    def list_remediations(self) -> List[Remediation]:
        return list(self._remediations.values())

    def get_remediation(self, remediation_id: str) -> Optional[Remediation]:
        return self._remediations.get(remediation_id)

    def save_campaign(self, campaign: PatchCampaign) -> PatchCampaign:
        with self._lock:
            self._campaigns[campaign.id] = campaign
        return campaign

    def list_campaigns(self) -> List[PatchCampaign]:
        return list(self._campaigns.values())

    def get_campaign(self, campaign_id: str) -> Optional[PatchCampaign]:
        return self._campaigns.get(campaign_id)


metadata = MetaData()
records = Table(
    "control_plane_records",
    metadata,
    Column("kind", String(32), primary_key=True),
    Column("id", String(96), primary_key=True),
    Column("host_id", String(96), nullable=True, index=True),
    Column("payload", JSON, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)


class SqlRepository(Repository):
    """JSON-backed SQL repository for PostgreSQL and local integration testing."""

    model_by_kind: Dict[str, Type[ModelT]] = {
        "host": Host,
        "scan": ScanJob,
        "finding": Finding,
        "remediation": Remediation,
        "campaign": PatchCampaign,
    }

    def __init__(self, database_url: str) -> None:
        self.engine: Engine = create_engine(database_url)
        metadata.create_all(self.engine)

    def _save(self, kind: str, item: ModelT, host_id: Optional[str] = None) -> ModelT:
        payload = item.model_dump(mode="json", by_alias=False)
        with self.engine.begin() as connection:
            connection.execute(
                delete(records).where(records.c.kind == kind, records.c.id == item.id)
            )
            connection.execute(
                records.insert().values(
                    kind=kind,
                    id=item.id,
                    host_id=host_id,
                    payload=payload,
                    updated_at=utc_now(),
                )
            )
        return item

    def _get(self, kind: str, item_id: str) -> Optional[ModelT]:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(records.c.payload).where(
                    records.c.kind == kind,
                    records.c.id == item_id,
                )
            ).first()
        if not row:
            return None
        return self.model_by_kind[kind].model_validate(row.payload)

    def _list(self, kind: str, host_id: Optional[str] = None) -> List[ModelT]:
        statement = select(records.c.payload).where(records.c.kind == kind)
        if host_id is not None:
            statement = statement.where(records.c.host_id == host_id)
        with self.engine.connect() as connection:
            rows = connection.execute(statement).all()
        model = self.model_by_kind[kind]
        return [model.model_validate(row.payload) for row in rows]

    def list_hosts(self) -> List[Host]:
        return self._list("host")

    def save_host(self, host: Host) -> Host:
        return self._save("host", host)

    def get_host(self, host_id: str) -> Optional[Host]:
        return self._get("host", host_id)

    def save_scan(self, scan: ScanJob) -> ScanJob:
        return self._save("scan", scan, scan.host_id)

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        return self._get("scan", scan_id)

    def save_findings(self, findings: List[Finding]) -> List[Finding]:
        for finding in findings:
            self._save("finding", finding, finding.host_id)
        return findings

    def list_findings(self, host_id: str) -> List[Finding]:
        return self._list("finding", host_id)

    def save_remediation(self, remediation: Remediation) -> Remediation:
        return self._save("remediation", remediation, remediation.host_id)

    def list_remediations(self) -> List[Remediation]:
        return self._list("remediation")

    def get_remediation(self, remediation_id: str) -> Optional[Remediation]:
        return self._get("remediation", remediation_id)

    def save_campaign(self, campaign: PatchCampaign) -> PatchCampaign:
        return self._save("campaign", campaign)

    def list_campaigns(self) -> List[PatchCampaign]:
        return self._list("campaign")

    def get_campaign(self, campaign_id: str) -> Optional[PatchCampaign]:
        return self._get("campaign", campaign_id)
