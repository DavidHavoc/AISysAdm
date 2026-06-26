from datetime import timedelta

import pytest

from sysadmin_api.credentials import CredentialService
from sysadmin_api.executor import SimulatedExecutor
from sysadmin_api.models import (
    ApprovalRequest,
    HostInput,
    PatchPolicy,
    ScanRequest,
    SnapshotHealthResult,
    SnapshotOperationResult,
)
from sysadmin_api.redaction import redact_payload
from sysadmin_api.snapshots import SimulatedSnapshotProvider


def host_input(name: str = "snapshot-web", **overrides) -> HostInput:
    values = {
        "name": name,
        "address": "10.0.0.40",
        "port": 22,
        "username": "ubuntu",
        "distro_family": "debian",
        "environment": "production",
        "tags": ["web"],
        "criticality": "high",
        "availability_class": "high_availability",
        "patch_policy": PatchPolicy(),
    }
    values.update(overrides)
    return HostInput(**values)


async def completed_scan(service, host):
    queued = service.create_scan_job(ScanRequest(host_id=host.id))
    completed = await service.process_scan(queued.id)
    return service.get_scan(completed.scan_id)


def approval_for(host, remediation):
    return ApprovalRequest(
        plan_version=remediation.plan_version,
        plan_hash=remediation.plan_hash,
        hostname_confirmation=host.name,
    )


def platform_credential(service, credential_type: str = "proxmox_token"):
    vault = CredentialService(service.repository, b"1" * 32)
    return vault.save_secret(
        "snapshot-platform",
        credential_type,
        b"super-secret-platform-token",
    )


async def approved_reboot_remediation(service, host):
    scan = await completed_scan(service, host)
    remediation = service.repository.get_remediation(scan.remediation_ids[0])
    service.approve_remediation_plan(remediation.id, approval_for(host, remediation), "admin")
    service.approve_remediation_reboot(remediation.id, approval_for(host, remediation), "admin")
    return service.repository.get_remediation(remediation.id)


class RecordingExecutor(SimulatedExecutor):
    def __init__(self, calls):
        self.calls = calls

    async def execute(self, host, remediation, job_id=""):
        self.calls.append("execute")
        return await super().execute(host, remediation, job_id)


class RecordingSnapshotProvider(SimulatedSnapshotProvider):
    def __init__(
        self,
        calls,
        fail_create=False,
        healthy=True,
        fail_rollback=False,
    ):
        self.calls = calls
        self.fail_create = fail_create
        self.healthy = healthy
        self.fail_rollback = fail_rollback

    async def create_snapshot(self, host, remediation, snapshot, job_id=""):
        self.calls.append("snapshot_create")
        if self.fail_create:
            return SnapshotOperationResult(success=False, summary="snapshot create failed")
        return await super().create_snapshot(host, remediation, snapshot, job_id)

    async def run_health_checks(self, host, remediation, snapshot, job_id=""):
        self.calls.append("health_check")
        if not self.healthy:
            return SnapshotHealthResult(
                healthy=False,
                summary="post reboot health failed",
                checks={"ssh_reachable": "failed"},
            )
        return await super().run_health_checks(host, remediation, snapshot, job_id)

    async def rollback_snapshot(self, host, remediation, snapshot, job_id=""):
        self.calls.append("rollback")
        if self.fail_rollback:
            return SnapshotOperationResult(success=False, summary="rollback failed")
        return await super().rollback_snapshot(host, remediation, snapshot, job_id)


def test_platform_credentials_are_encrypted_and_snapshot_metadata_is_redacted(service):
    credential = platform_credential(service)
    record = service.repository.get_credential_record(credential.id)

    assert credential.credential_type == "proxmox_token"
    assert record is not None
    assert b"super-secret-platform-token" not in record[1]
    assert redact_payload(
        {
            "snapshotCredentialId": credential.id,
            "snapshotProviderMetadata": {"token": "super-secret-platform-token"},
        }
    ) == {
        "snapshotCredentialId": "[CREDENTIAL]",
        "snapshotProviderMetadata": "[PROVIDER_METADATA]",
    }


def test_host_snapshot_validation_requires_matching_credential(service):
    vault = CredentialService(service.repository, b"2" * 32)
    ssh_credential = vault.save_private_key(
        "ssh",
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----",
    )

    with pytest.raises(ValueError, match="Allowed type"):
        service.create_host(
            host_input(
                snapshot_platform="proxmox",
                snapshot_credential_id=ssh_credential.id,
                snapshot_target_id="vm-100",
            )
        )


@pytest.mark.asyncio
async def test_reboot_risk_remediation_creates_snapshot_before_update(service):
    calls = []
    service.snapshot_provider = RecordingSnapshotProvider(calls)
    service.executor = RecordingExecutor(calls)
    credential = platform_credential(service)
    host = service.create_host(
        host_input(
            snapshot_platform="proxmox",
            snapshot_credential_id=credential.id,
            snapshot_target_id="vm-100",
        )
    )
    remediation = await approved_reboot_remediation(service, host)

    queued = service.prepare_remediation_job(remediation.id, "admin")
    completed = await service.process_remediation(queued.id)
    snapshots = service.list_rollback_snapshots(remediation_id=remediation.id)
    delete_jobs = [
        item for item in service.list_jobs() if item.job_type == "snapshot_delete"
    ]

    assert completed.status == "completed"
    assert calls[:3] == ["snapshot_create", "execute", "health_check"]
    assert snapshots[0].state == "delete_scheduled"
    assert snapshots[0].delete_after is not None
    assert snapshots[0].delete_after - snapshots[0].created_at >= timedelta(days=6)
    assert delete_jobs and delete_jobs[0].status == "scheduled"


@pytest.mark.asyncio
async def test_snapshot_creation_failure_blocks_patching(service):
    calls = []
    service.snapshot_provider = RecordingSnapshotProvider(calls, fail_create=True)
    service.executor = RecordingExecutor(calls)
    credential = platform_credential(service)
    host = service.create_host(
        host_input(
            snapshot_platform="proxmox",
            snapshot_credential_id=credential.id,
            snapshot_target_id="vm-100",
        )
    )
    remediation = await approved_reboot_remediation(service, host)

    queued = service.prepare_remediation_job(remediation.id, "admin")
    failed = await service.process_remediation(queued.id)
    blocked = service.repository.get_remediation(remediation.id)

    assert failed.status == "failed"
    assert calls == ["snapshot_create"]
    assert blocked.execution_state == "blocked"
    assert "Snapshot creation failed" in failed.error


@pytest.mark.asyncio
async def test_unhealthy_post_reboot_checks_trigger_rollback_and_alert(service):
    calls = []
    service.snapshot_provider = RecordingSnapshotProvider(calls, healthy=False)
    credential = platform_credential(service)
    host = service.create_host(
        host_input(
            snapshot_platform="proxmox",
            snapshot_credential_id=credential.id,
            snapshot_target_id="vm-100",
        )
    )
    remediation = await approved_reboot_remediation(service, host)

    queued = service.prepare_remediation_job(remediation.id, "admin")
    failed = await service.process_remediation(queued.id)
    snapshot = service.list_rollback_snapshots(remediation_id=remediation.id)[0]
    alerts = service.list_alerts()

    assert failed.status == "failed"
    assert calls == ["snapshot_create", "health_check", "rollback"]
    assert snapshot.state == "rolled_back"
    assert service.repository.get_remediation(remediation.id).execution_state == "blocked"
    assert any("rollback completed" in alert.title.lower() for alert in alerts)


@pytest.mark.asyncio
async def test_rollback_failure_creates_critical_alert_and_blocks_host(service):
    calls = []
    service.snapshot_provider = RecordingSnapshotProvider(
        calls,
        healthy=False,
        fail_rollback=True,
    )
    credential = platform_credential(service)
    host = service.create_host(
        host_input(
            snapshot_platform="proxmox",
            snapshot_credential_id=credential.id,
            snapshot_target_id="vm-100",
        )
    )
    remediation = await approved_reboot_remediation(service, host)

    queued = service.prepare_remediation_job(remediation.id, "admin")
    failed = await service.process_remediation(queued.id)
    snapshot = service.list_rollback_snapshots(remediation_id=remediation.id)[0]
    alerts = service.list_alerts()

    assert failed.status == "failed"
    assert snapshot.state == "rollback_failed"
    assert any(
        alert.severity == "critical" and alert.title == "Snapshot rollback failed"
        for alert in alerts
    )
    assert service._host_has_active_rollback_failure(host.id) is True
