from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from sysadmin_api.config import BEAT_HEALTH_KEY, WORKER_HEALTH_KEY
from sysadmin_api.main import create_app
from sysadmin_api.models import (
    ApprovalRequest,
    HostInput,
    PatchPolicy,
    ScanRequest,
    utc_now,
)
from sysadmin_api.queue import InlineJobDispatcher
from sysadmin_api.redaction import sanitize_celery_payload


pytestmark = [
    pytest.mark.integration,
    pytest.mark.real_host,
    pytest.mark.ansible,
]


def login(client: TestClient) -> str:
    response = client.post(
        "/auth/login",
        json={
            "username": "integration-admin",
            "password": "integration-test-password",
        },
    )
    assert response.status_code == 200
    return response.json()["csrfToken"]


def reset_target(target) -> None:
    target.ssh("sudo rm -f /var/run/reboot-required /tmp/ai-sysadm-no-updates")


def host_input(target, credential_id: str, name: str, update_mode: str = "security"):
    return HostInput(
        name=name,
        address=target.address,
        port=target.port,
        username=target.username,
        environment="integration",
        tags=["real-host", target.name],
        credential_id=credential_id,
        patch_policy=PatchPolicy(update_mode=update_mode),
    )


def approval_for(host, remediation):
    return ApprovalRequest(
        plan_version=remediation.plan_version,
        plan_hash=remediation.plan_hash,
        hostname_confirmation=host.name,
    )


async def confirmed_real_host(runtime, target, name: str, update_mode: str = "security"):
    credential = runtime.credentials.save_private_key(
        "%s-key" % name,
        target.private_key,
    )
    host = runtime.service.create_host(
        host_input(target, credential.id, name, update_mode),
        "integration-admin",
    )
    first = await runtime.service.test_connection(host.id, None, "integration-admin")
    assert first.success is False
    assert first.ssh_reachable is True
    assert first.sudo_available is True
    assert first.host_key_fingerprint
    assert first.checks["host_key_confirmation"] == "required"

    confirmed = await runtime.service.test_connection(
        host.id,
        first.host_key_fingerprint,
        "integration-admin",
    )
    assert confirmed.success is True
    return runtime.repository.get_host(host.id)


async def completed_scan(runtime, host, trigger: str = "manual"):
    job = runtime.service.create_scan_job(
        ScanRequest(
            host_id=host.id,
            trigger=trigger,
            idempotency_key="%s:%s" % (trigger, host.id),
        ),
        actor="scheduler" if trigger == "scheduled" else "integration-admin",
    )
    completed = await runtime.service.process_scan(job.id, "%s-worker" % trigger)
    assert completed.status == "completed"
    return runtime.service.get_scan(completed.scan_id)


def log_items(runtime, **filters):
    return runtime.service.list_logs(filters, 1, 200).items


def log_blob(events) -> str:
    return "\n".join(
        "\n".join(
            [
                event.stdout or "",
                event.stderr or "",
                event.raw_output or "",
                event.command_description or "",
            ]
        )
        for event in events
    )


def assert_secret_redacted(value: str) -> None:
    assert "super-secret-token" not in value
    assert "Bearer super-secret-token" not in value
    assert "[TOKEN]" in value or "[AUTHORIZATION]" in value


def test_ssh_credentials_and_host_key_confirmation_via_api(
    real_host_runtime,
    real_host_target,
):
    reset_target(real_host_target)
    client = TestClient(
        create_app(
            runtime=real_host_runtime,
            dispatcher=InlineJobDispatcher(real_host_runtime.service),
        )
    )
    csrf = login(client)
    headers = {"X-CSRF-Token": csrf}

    credential_response = client.post(
        "/credentials",
        headers=headers,
        data={"name": "real-host-api-key"},
        files={
            "key": (
                "id_ed25519",
                real_host_target.private_key,
                "application/octet-stream",
            )
        },
    )
    assert credential_response.status_code == 201
    credential = credential_response.json()

    host_response = client.post(
        "/hosts",
        headers=headers,
        json={
            "name": "real-host-api",
            "address": real_host_target.address,
            "port": real_host_target.port,
            "username": real_host_target.username,
            "credentialId": credential["id"],
            "patchPolicy": {"updateMode": "security"},
        },
    )
    assert host_response.status_code == 201
    host = host_response.json()

    first = client.post(
        "/hosts/%s/test-connection" % host["id"],
        headers=headers,
        json={},
    )
    assert first.status_code == 200
    first_result = first.json()
    assert first_result["success"] is False
    assert first_result["sshReachable"] is True
    assert first_result["sudoAvailable"] is True
    assert first_result["osSupported"] is True
    assert first_result["ansibleCompatible"] is True
    assert first_result["hostKeyFingerprint"].startswith("SHA256:")
    assert first_result["checks"]["host_key_confirmation"] == "required"

    confirmed = client.post(
        "/hosts/%s/test-connection" % host["id"],
        headers=headers,
        json={"confirmFingerprint": first_result["hostKeyFingerprint"]},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["success"] is True

    hosts = client.get("/hosts").json()
    saved = next(item for item in hosts if item["id"] == host["id"])
    assert saved["connectionStatus"] == "ready"
    assert saved["sshHostKeyFingerprint"] == first_result["hostKeyFingerprint"]

    wrong_host_response = client.post(
        "/hosts",
        headers=headers,
        json={
            "name": "real-host-wrong-fingerprint",
            "address": real_host_target.address,
            "port": real_host_target.port,
            "username": real_host_target.username,
            "credentialId": credential["id"],
        },
    )
    assert wrong_host_response.status_code == 201
    wrong_host = wrong_host_response.json()
    wrong = client.post(
        "/hosts/%s/test-connection" % wrong_host["id"],
        headers=headers,
        json={"confirmFingerprint": "SHA256:not-the-target"},
    )
    assert wrong.status_code == 200
    assert wrong.json()["success"] is False
    assert wrong.json()["checks"]["host_key_confirmation"] == "required"
    hosts = client.get("/hosts").json()
    saved_wrong = next(item for item in hosts if item["id"] == wrong_host["id"])
    assert saved_wrong["connectionStatus"] == "untested"
    assert saved_wrong["sshHostKeyFingerprint"] is None

    delete_attached = client.delete(
        "/credentials/%s" % credential["id"],
        headers=headers,
    )
    assert delete_attached.status_code == 409
    assert "real-host-api" in delete_attached.json()["detail"]
    assert "Remove it from those hosts" in delete_attached.json()["detail"]


@pytest.mark.asyncio
async def test_real_ssh_scan_persists_evidence_analysis_and_observability(
    real_host_runtime,
    real_host_target,
    redis_client,
):
    reset_target(real_host_target)
    host = await confirmed_real_host(
        real_host_runtime,
        real_host_target,
        "real-host-scan",
    )
    job = real_host_runtime.service.create_scan_job(ScanRequest(host_id=host.id))

    first, duplicate = await asyncio.gather(
        real_host_runtime.service.process_scan(job.id, "scan-worker-1"),
        real_host_runtime.service.process_scan(job.id, "scan-worker-2"),
    )

    stored_job = real_host_runtime.repository.get_job(job.id)
    scan = real_host_runtime.service.get_scan(stored_job.scan_id)
    snapshot = real_host_runtime.repository.get_snapshot(scan.snapshot_id)
    evidence_logs = log_items(real_host_runtime, scan_id=scan.id)

    assert {first.status, duplicate.status} <= {"running", "completed"}
    assert stored_job.status == "completed"
    assert stored_job.attempts == 1
    assert scan.status == "completed"
    assert snapshot.package_summary.pending_package_updates == 3
    assert snapshot.package_summary.pending_security_updates == 2
    assert snapshot.service_summary.degraded is False
    assert snapshot.system_summary.kernel_version
    assert snapshot.system_summary.boot_id
    assert snapshot.network_summary.interfaces
    assert snapshot.network_summary.default_routes
    assert snapshot.logs.journal
    assert snapshot.logs.kernel
    assert snapshot.logs.auth
    assert snapshot.logs.apt_history
    assert "reboot_history" in snapshot.commands
    assert {"journal", "kernel_journal", "auth", "apt_history"} <= set(
        snapshot.evidence_states
    )
    assert any(
        state.status in {"truncated", "unavailable"}
        for state in snapshot.evidence_states.values()
    )
    assert any(event.event_type == "evidence_collected" for event in evidence_logs)
    assert any(event.source == "ssh:auth" and event.redacted for event in evidence_logs)
    auth_logs = [event for event in evidence_logs if event.source == "ssh:auth"]
    assert real_host_target.username not in snapshot.logs.auth
    assert real_host_target.username not in log_blob(auth_logs)
    assert "172.18.0.1" not in log_blob(auth_logs)

    findings = real_host_runtime.service.list_findings(host.id)
    remediation = real_host_runtime.repository.get_remediation(scan.remediation_ids[0])
    assert findings
    assert remediation.update_scope == "security"
    assert remediation.reboot_assessment.status == "required_after_patch"
    assert real_host_runtime.service.list_agent_runs(scan.id)
    assert real_host_runtime.service.list_agent_messages(scan.id)

    scheduled = await completed_scan(real_host_runtime, host, trigger="scheduled")
    assert scheduled.status == "completed"
    assert real_host_runtime.service.list_alerts()

    redis_client.set(WORKER_HEALTH_KEY, utc_now().isoformat(), ex=60)
    redis_client.set(BEAT_HEALTH_KEY, utc_now().isoformat(), ex=60)
    client = TestClient(create_app(runtime=real_host_runtime))
    ready = client.get("/health/ready")
    ops = client.get("/health/ops")
    assert ready.status_code == 200
    assert ready.json()["checks"]["collectorMode"] == "ssh"
    assert ready.json()["checks"]["executionMode"] == "ansible"
    assert ops.status_code == 200


@pytest.mark.asyncio
async def test_ansible_execution_records_safe_catalog_phases(
    real_host_runtime,
    real_host_target,
):
    reset_target(real_host_target)
    host = await confirmed_real_host(
        real_host_runtime,
        real_host_target,
        "real-host-ansible",
    )
    scan = await completed_scan(real_host_runtime, host)
    remediation = real_host_runtime.repository.get_remediation(scan.remediation_ids[0])

    with pytest.raises(ValueError, match="hostname"):
        real_host_runtime.service.approve_remediation_plan(
            remediation.id,
            ApprovalRequest(
                plan_version=remediation.plan_version,
                plan_hash=remediation.plan_hash,
                hostname_confirmation="wrong-host",
            ),
            "integration-admin",
        )
    with pytest.raises(ValueError, match="changed"):
        real_host_runtime.service.approve_remediation_plan(
            remediation.id,
            ApprovalRequest(
                plan_version=remediation.plan_version,
                plan_hash="wrong-hash",
                hostname_confirmation=host.name,
            ),
            "integration-admin",
        )

    approved = real_host_runtime.service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "integration-admin",
    )
    assert approved.reboot_approval_state == "pending"
    with pytest.raises(ValueError, match="reboot approval"):
        real_host_runtime.service.prepare_remediation_job(
            remediation.id,
            "integration-admin",
        )
    real_host_runtime.service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, remediation),
        "integration-admin",
    )
    queued = real_host_runtime.service.prepare_remediation_job(
        remediation.id,
        "integration-admin",
    )
    completed, duplicate = await asyncio.gather(
        real_host_runtime.service.process_remediation(
            queued.id,
            "ansible-worker-1",
        ),
        real_host_runtime.service.process_remediation(
            queued.id,
            "ansible-worker-2",
        ),
    )
    stored_job = real_host_runtime.repository.get_job(queued.id)
    final_remediation = real_host_runtime.repository.get_remediation(remediation.id)
    events = log_items(real_host_runtime, remediation_id=remediation.id)
    blob = log_blob(events) + "\n" + str(
        final_remediation.result.model_dump(mode="json")
    )

    assert {completed.status, duplicate.status} <= {"running", "completed"}
    assert stored_job.status == "completed"
    assert stored_job.attempts == 1
    assert final_remediation.execution_state == "succeeded"
    assert final_remediation.result.success is True
    assert [
        phase.name
        for phase in final_remediation.result.phases
    ] == [
        "pre_patch_check",
        "package_upgrade",
        "reboot_required_check",
        "post_patch_validation",
    ]
    assert {
        "pre-patch-check",
        "security-upgrade",
        "reboot-required-check",
        "post-patch-validation",
    } <= {event.playbook_id for event in events}
    assert "patch.packages.refresh" in {event.task_id for event in events}
    assert "patch.packages.security_upgrade" in {event.task_id for event in events}
    assert any(event.event_type == "ansible_task" for event in events)
    assert_secret_redacted(blob)

    unsupported_action = final_remediation.model_copy(deep=True)
    unsupported_action.action_type = "shell_command"
    action_result = await real_host_runtime.service.executor.execute(
        host,
        unsupported_action,
        "unsupported-action-job",
    )
    assert action_result.success is False
    assert "action type is not cataloged" in action_result.summary

    unsupported_scope = final_remediation.model_copy(deep=True)
    unsupported_scope.update_scope = "none"
    scope_result = await real_host_runtime.service.executor.execute(
        host,
        unsupported_scope,
        "unsupported-scope-job",
    )
    assert scope_result.success is False
    assert "update scope is not cataloged" in scope_result.summary


@pytest.mark.asyncio
async def test_plan_binding_and_real_host_drift_block_execution(
    real_host_runtime,
    real_host_target,
):
    reset_target(real_host_target)
    host = await confirmed_real_host(
        real_host_runtime,
        real_host_target,
        "real-host-binding",
    )
    scan = await completed_scan(real_host_runtime, host)
    remediation = real_host_runtime.repository.get_remediation(scan.remediation_ids[0])
    real_host_runtime.service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "integration-admin",
    )
    real_host_runtime.service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, remediation),
        "integration-admin",
    )
    queued = real_host_runtime.service.prepare_remediation_job(
        remediation.id,
        "integration-admin",
    )
    changed = real_host_runtime.repository.get_remediation(remediation.id)
    changed.update_scope = "all"
    real_host_runtime.repository.save_remediation(changed)

    binding_failed = await real_host_runtime.service.process_remediation(
        queued.id,
        "binding-worker",
    )
    binding_remediation = real_host_runtime.repository.get_remediation(remediation.id)
    binding_events = log_items(real_host_runtime, remediation_id=remediation.id)

    assert binding_failed.status == "failed"
    assert binding_failed.last_failure.category == "approval_validation"
    assert binding_failed.last_failure.retryable is False
    assert binding_remediation.execution_state == "blocked"
    assert not [event for event in binding_events if event.event_type == "ansible_task"]

    reset_target(real_host_target)
    drift_host = await confirmed_real_host(
        real_host_runtime,
        real_host_target,
        "real-host-drift",
    )
    drift_scan = await completed_scan(real_host_runtime, drift_host)
    drift_remediation = real_host_runtime.repository.get_remediation(
        drift_scan.remediation_ids[0]
    )
    real_host_runtime.service.approve_remediation_plan(
        drift_remediation.id,
        approval_for(drift_host, drift_remediation),
        "integration-admin",
    )
    real_host_runtime.service.approve_remediation_reboot(
        drift_remediation.id,
        approval_for(drift_host, drift_remediation),
        "integration-admin",
    )
    drift_job = real_host_runtime.service.prepare_remediation_job(
        drift_remediation.id,
        "integration-admin",
    )
    real_host_target.ssh(
        "printf 'reboot required\n' | sudo tee /var/run/reboot-required >/dev/null"
    )

    drift_failed = await real_host_runtime.service.process_remediation(
        drift_job.id,
        "drift-worker",
    )
    duplicate = await real_host_runtime.service.process_remediation(
        drift_job.id,
        "drift-worker-duplicate",
    )
    blocked = real_host_runtime.repository.get_remediation(drift_remediation.id)
    drift_logs = log_items(real_host_runtime, job_id=drift_job.id)
    audits = real_host_runtime.service.list_audits()
    alerts = real_host_runtime.service.list_alerts()

    assert drift_failed.status == "failed"
    assert drift_failed.attempts == 1
    assert drift_failed.last_failure.category == "safety_validation"
    assert drift_failed.last_failure.retryable is False
    assert duplicate.attempts == 1
    assert "changed after approval" in drift_failed.error
    assert blocked.execution_state == "blocked"
    assert any(event.event_type == "evidence_collected" for event in drift_logs)
    assert not [
        event
        for event in log_items(real_host_runtime, remediation_id=drift_remediation.id)
        if event.event_type == "ansible_task"
    ]
    assert any(event.action == "job.failed" for event in audits)
    assert any(alert.job_id == drift_job.id for alert in alerts)


@pytest.mark.asyncio
async def test_real_host_job_durability_retries_and_payload_sanitization(
    real_host_runtime,
    real_host_target,
):
    reset_target(real_host_target)

    class SlowCollector:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        async def test_connection(self, host):
            return await self.wrapped.test_connection(host)

        async def collect(self, host, job_id="", scan_id=""):
            await asyncio.sleep(2.2)
            return await self.wrapped.collect(host, job_id, scan_id)

    host = await confirmed_real_host(
        real_host_runtime,
        real_host_target,
        "real-host-heartbeat",
    )
    original_collector = real_host_runtime.service.collector
    real_host_runtime.service.collector = SlowCollector(original_collector)
    scan_job = real_host_runtime.service.create_scan_job(ScanRequest(host_id=host.id))
    scan_task = asyncio.create_task(
        real_host_runtime.service.process_scan(scan_job.id, "slow-scan-worker")
    )
    await asyncio.sleep(1.4)
    running_scan = real_host_runtime.repository.get_job(scan_job.id)
    completed = await scan_task
    real_host_runtime.service.collector = original_collector

    assert running_scan.status == "running"
    assert running_scan.heartbeat_at is not None
    assert running_scan.started_at is not None
    assert running_scan.heartbeat_at > running_scan.started_at
    assert completed.status == "completed"
    assert real_host_runtime.repository.get_job(scan_job.id).attempts == 1

    scan = real_host_runtime.service.get_scan(completed.scan_id)
    remediation = real_host_runtime.repository.get_remediation(scan.remediation_ids[0])
    real_host_runtime.service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "integration-admin",
    )
    real_host_runtime.service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, remediation),
        "integration-admin",
    )

    class SlowExecutor:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        async def execute(self, host, remediation, job_id=""):
            await asyncio.sleep(2.2)
            return await self.wrapped.execute(host, remediation, job_id)

    original_executor = real_host_runtime.service.executor
    real_host_runtime.service.executor = SlowExecutor(original_executor)
    remediation_job = real_host_runtime.service.prepare_remediation_job(
        remediation.id,
        "integration-admin",
    )
    remediation_task = asyncio.create_task(
        real_host_runtime.service.process_remediation(
            remediation_job.id,
            "slow-remediation-worker",
        )
    )
    await asyncio.sleep(1.4)
    running_remediation = real_host_runtime.repository.get_job(remediation_job.id)
    remediation_completed = await remediation_task
    real_host_runtime.service.executor = original_executor

    assert running_remediation.status == "running"
    assert running_remediation.heartbeat_at is not None
    assert running_remediation.started_at is not None
    assert running_remediation.heartbeat_at > running_remediation.started_at
    assert remediation_completed.status == "completed"
    assert real_host_runtime.repository.get_job(remediation_job.id).attempts == 1

    credential = real_host_runtime.credentials.save_private_key(
        "retry-key",
        real_host_target.private_key,
    )
    retry_host = real_host_runtime.service.create_host(
        HostInput(
            name="real-host-retry",
            address="127.0.0.1",
            port=1,
            username=real_host_target.username,
            credential_id=credential.id,
            ssh_host_key_fingerprint="SHA256:closed-loopback-port",
        ),
        "integration-admin",
    )
    retry_job = real_host_runtime.service.create_scan_job(
        ScanRequest(host_id=retry_host.id)
    )
    first = await real_host_runtime.service.process_scan(retry_job.id, "retry-1")
    second = await real_host_runtime.service.process_scan(retry_job.id, "retry-2")
    third = await real_host_runtime.service.process_scan(retry_job.id, "retry-3")

    assert first.status == "queued"
    assert second.status == "queued"
    assert third.status == "failed"
    assert third.attempts == third.max_attempts == 3
    assert third.last_failure.retryable is False

    stale_job = real_host_runtime.service.create_scan_job(
        ScanRequest(
            host_id=host.id,
            idempotency_key="stale-real-host-scan",
        )
    )
    now = utc_now()
    real_host_runtime.repository.claim_job(
        stale_job.id,
        "crashed-real-worker",
        now,
        now + timedelta(seconds=5),
    )
    recovered = real_host_runtime.service.recover_expired_jobs(
        now + timedelta(seconds=6)
    )
    recovered_job = real_host_runtime.repository.get_job(stale_job.id)
    assert [item.id for item in recovered] == [stale_job.id]
    assert recovered_job.status == "queued"
    assert recovered_job.current_phase == "retry_scheduled"

    payload = sanitize_celery_payload(
        {
            "job": {
                "stderr": "token=super-secret-token",
                "authorization": "Bearer super-secret-token",
            }
        }
    )
    assert_secret_redacted(str(payload))
