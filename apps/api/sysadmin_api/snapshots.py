from __future__ import annotations

import asyncio
import json
import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from .credentials import CredentialService
from .models import (
    Host,
    Remediation,
    RollbackSnapshot,
    Severity,
    SnapshotHealthResult,
    SnapshotOperationResult,
    SnapshotPlatform,
    StructuredLogEvent,
    utc_now,
)
from .redaction import redact_text, sanitize_log_event
from .ssh_utils import scan_host_key, temporary_known_hosts


SNAPSHOT_PLAYBOOK_CATALOG = {
    "simulated_create": "simulated-create.yml",
    "simulated_delete": "simulated-delete.yml",
    "simulated_rollback": "simulated-rollback.yml",
    "proxmox_create": "proxmox-create.yml",
    "proxmox_delete": "proxmox-delete.yml",
    "proxmox_rollback": "proxmox-rollback.yml",
    "health_check": "health-check.yml",
}


class SnapshotProvider(ABC):
    @abstractmethod
    async def create_snapshot(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        raise NotImplementedError

    @abstractmethod
    async def delete_snapshot(
        self,
        host: Host,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        raise NotImplementedError

    @abstractmethod
    async def rollback_snapshot(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        raise NotImplementedError

    @abstractmethod
    async def run_health_checks(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotHealthResult:
        raise NotImplementedError


class SimulatedSnapshotProvider(SnapshotProvider):
    async def create_snapshot(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        if host.snapshot_provider_metadata.get("simulateSnapshotCreateFailure"):
            return SnapshotOperationResult(
                success=False,
                summary="Simulated snapshot creation failed.",
                events=[
                    snapshot_event(
                        host,
                        remediation,
                        job_id,
                        "snapshot_create",
                        "failed",
                        "Simulated snapshot creation failed.",
                    )
                ],
            )
        external_id = "sim-%s" % uuid4().hex[:12]
        return SnapshotOperationResult(
            success=True,
            external_snapshot_id=external_id,
            summary="Simulated snapshot was created.",
            events=[
                snapshot_event(
                    host,
                    remediation,
                    job_id,
                    "snapshot_create",
                    "succeeded",
                    "Simulated snapshot was created.",
                    external_snapshot_id=external_id,
                )
            ],
        )

    async def delete_snapshot(
        self,
        host: Host,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        return SnapshotOperationResult(
            success=True,
            external_snapshot_id=snapshot.external_snapshot_id,
            summary="Simulated snapshot deletion completed.",
            events=[
                snapshot_event(
                    host,
                    None,
                    job_id,
                    "snapshot_delete",
                    "succeeded",
                    "Simulated snapshot deletion completed.",
                    snapshot,
                )
            ],
        )

    async def rollback_snapshot(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        if host.snapshot_provider_metadata.get("simulateRollbackFailure"):
            return SnapshotOperationResult(
                success=False,
                external_snapshot_id=snapshot.external_snapshot_id,
                summary="Simulated snapshot rollback failed.",
                events=[
                    snapshot_event(
                        host,
                        remediation,
                        job_id,
                        "snapshot_rollback",
                        "failed",
                        "Simulated snapshot rollback failed.",
                        snapshot,
                    )
                ],
            )
        return SnapshotOperationResult(
            success=True,
            external_snapshot_id=snapshot.external_snapshot_id,
            summary="Simulated snapshot rollback completed.",
            events=[
                snapshot_event(
                    host,
                    remediation,
                    job_id,
                    "snapshot_rollback",
                    "succeeded",
                    "Simulated snapshot rollback completed.",
                    snapshot,
                )
            ],
        )

    async def run_health_checks(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotHealthResult:
        checks = {"ssh_reachable": "passed"}
        if host.critical_service_name:
            checks["critical_service"] = "passed"
        if host.health_check_url:
            checks["health_url"] = "passed"
        if host.snapshot_provider_metadata.get("simulateUnhealthyAfterReboot"):
            checks["ssh_reachable"] = "failed"
        healthy = all(value == "passed" for value in checks.values())
        summary = (
            "Deterministic post-reboot health checks passed."
            if healthy
            else "Deterministic post-reboot health checks failed."
        )
        return SnapshotHealthResult(
            healthy=healthy,
            summary=summary,
            checks=checks,
            events=[
                snapshot_event(
                    host,
                    remediation,
                    job_id,
                    "post_reboot_health_check",
                    "succeeded" if healthy else "failed",
                    summary,
                    snapshot,
                )
            ],
        )


class AnsibleSnapshotProvider(SnapshotProvider):
    def __init__(
        self,
        playbook_dir: Path,
        callback_dir: Path,
        credentials: CredentialService,
    ) -> None:
        self.playbook_dir = playbook_dir
        self.callback_dir = callback_dir
        self.credentials = credentials

    async def create_snapshot(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        key = "%s_create" % host.snapshot_platform
        success, output, events = await self._run_snapshot_playbook(
            host,
            remediation,
            snapshot,
            job_id,
            "snapshot_create",
            SNAPSHOT_PLAYBOOK_CATALOG.get(key, "simulated-create.yml"),
        )
        external_id = parse_external_snapshot_id(output) or "snapshot-%s" % uuid4().hex[:12]
        return SnapshotOperationResult(
            success=success,
            external_snapshot_id=external_id if success else None,
            summary=(
                "Snapshot creation completed."
                if success
                else "Snapshot creation failed."
            ),
            events=events,
        )

    async def delete_snapshot(
        self,
        host: Host,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        key = "%s_delete" % snapshot.provider
        success, _, events = await self._run_snapshot_playbook(
            host,
            None,
            snapshot,
            job_id,
            "snapshot_delete",
            SNAPSHOT_PLAYBOOK_CATALOG.get(key, "simulated-delete.yml"),
        )
        return SnapshotOperationResult(
            success=success,
            external_snapshot_id=snapshot.external_snapshot_id,
            summary=(
                "Snapshot deletion completed."
                if success
                else "Snapshot deletion failed."
            ),
            events=events,
        )

    async def rollback_snapshot(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotOperationResult:
        key = "%s_rollback" % snapshot.provider
        success, _, events = await self._run_snapshot_playbook(
            host,
            remediation,
            snapshot,
            job_id,
            "snapshot_rollback",
            SNAPSHOT_PLAYBOOK_CATALOG.get(key, "simulated-rollback.yml"),
        )
        return SnapshotOperationResult(
            success=success,
            external_snapshot_id=snapshot.external_snapshot_id,
            summary=(
                "Snapshot rollback completed."
                if success
                else "Snapshot rollback failed."
            ),
            events=events,
        )

    async def run_health_checks(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str = "",
    ) -> SnapshotHealthResult:
        if not host.ssh_host_key_fingerprint:
            return SnapshotHealthResult(
                healthy=False,
                summary="SSH host key has not been confirmed.",
                checks={"ssh_reachable": "failed"},
            )
        known_line, fingerprint = await scan_host_key(host.address, host.port)
        if fingerprint != host.ssh_host_key_fingerprint:
            return SnapshotHealthResult(
                healthy=False,
                summary="SSH host key changed before health checks.",
                checks={"ssh_reachable": "failed"},
            )
        with self.credentials.temporary_key(host.credential_id) as key_path:
            with temporary_known_hosts(known_line) as known_hosts:
                success, output, events = await self._run_health_playbook(
                    host,
                    remediation,
                    snapshot,
                    job_id,
                    str(key_path),
                    str(known_hosts),
                )
        checks = parse_health_checks(output)
        if not checks:
            checks = {"ansible_health_playbook": "passed" if success else "failed"}
        return SnapshotHealthResult(
            healthy=success and all(value == "passed" for value in checks.values()),
            summary=(
                "Deterministic post-reboot health checks passed."
                if success
                else "Deterministic post-reboot health checks failed."
            ),
            checks=checks,
            events=events,
        )

    async def _run_snapshot_playbook(
        self,
        host: Host,
        remediation: Optional[Remediation],
        snapshot: RollbackSnapshot,
        job_id: str,
        phase_id: str,
        playbook: str,
    ) -> Tuple[bool, str, List[StructuredLogEvent]]:
        with self.credentials.temporary_secret(host.snapshot_credential_id) as secret_path:
            vars_payload = {
                "snapshot_provider": host.snapshot_platform,
                "snapshot_target_id": host.snapshot_target_id,
                "snapshot_metadata": host.snapshot_provider_metadata,
                "snapshot_secret_file": str(secret_path),
                "external_snapshot_id": snapshot.external_snapshot_id or "",
            }
            return await self._run_playbook(
                host,
                remediation,
                snapshot,
                job_id,
                phase_id,
                playbook,
                vars_payload,
            )

    async def _run_health_playbook(
        self,
        host: Host,
        remediation: Remediation,
        snapshot: RollbackSnapshot,
        job_id: str,
        key_path: str,
        known_hosts_path: str,
    ) -> Tuple[bool, str, List[StructuredLogEvent]]:
        vars_payload = {
            "critical_service_name": host.critical_service_name or "",
            "health_check_url": host.health_check_url or "",
        }
        return await self._run_playbook(
            host,
            remediation,
            snapshot,
            job_id,
            "post_reboot_health_check",
            SNAPSHOT_PLAYBOOK_CATALOG["health_check"],
            vars_payload,
            inventory="%s," % host.address,
            extra_args=[
                "-u",
                host.username,
                "--private-key",
                key_path,
                "-e",
                "ansible_port=%s" % host.port,
                "-e",
                (
                    "ansible_ssh_common_args=-o StrictHostKeyChecking=yes "
                    "-o UserKnownHostsFile=%s" % known_hosts_path
                ),
            ],
        )

    async def _run_playbook(
        self,
        host: Host,
        remediation: Optional[Remediation],
        snapshot: RollbackSnapshot,
        job_id: str,
        phase_id: str,
        playbook: str,
        vars_payload: Dict[str, Any],
        inventory: str = "localhost,",
        extra_args: Optional[List[str]] = None,
    ) -> Tuple[bool, str, List[StructuredLogEvent]]:
        event_descriptor, event_path_raw = tempfile.mkstemp(
            prefix="ai-sysadm-snapshot-events-",
            suffix=".jsonl",
        )
        os.close(event_descriptor)
        vars_descriptor, vars_path_raw = tempfile.mkstemp(
            prefix="ai-sysadm-snapshot-vars-",
            suffix=".json",
        )
        event_path = Path(event_path_raw)
        vars_path = Path(vars_path_raw)
        safe_payload = dict(vars_payload)
        safe_payload["snapshot_metadata"] = "[PROVIDER_METADATA]"
        try:
            with os.fdopen(vars_descriptor, "w", encoding="utf-8") as handle:
                json.dump(vars_payload, handle)
                handle.flush()
                os.fsync(handle.fileno())
            environment = os.environ.copy()
            environment.update(
                {
                    "ANSIBLE_CALLBACK_PLUGINS": str(self.callback_dir),
                    "ANSIBLE_CALLBACKS_ENABLED": "ai_jsonl",
                    "AI_SYSADM_EVENT_FILE": str(event_path),
                    "AI_SYSADM_JOB_ID": job_id,
                    "AI_SYSADM_HOST_ID": host.id,
                    "AI_SYSADM_SCAN_ID": remediation.scan_id if remediation else "",
                    "AI_SYSADM_REMEDIATION_ID": (
                        remediation.id if remediation else snapshot.remediation_id
                    ),
                    "AI_SYSADM_PHASE_ID": phase_id,
                    "AI_SYSADM_PLAYBOOK_ID": Path(playbook).stem,
                }
            )
            command = [
                "ansible-playbook",
                "-i",
                inventory,
                str(self.playbook_dir / playbook),
                "-e",
                "@%s" % vars_path,
            ]
            if extra_args:
                command.extend(extra_args)
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )
            stdout, stderr = await process.communicate()
            output = "\n".join(
                value.decode(errors="replace").strip()
                for value in (stdout, stderr)
                if value
            )
            events = parse_snapshot_callback_events(event_path, host)
            if not events:
                events = [
                    sanitize_log_event(
                        StructuredLogEvent(
                            id="log-%s" % uuid4().hex[:12],
                            timestamp=utc_now(),
                            host_id=host.id,
                            job_id=job_id or None,
                            scan_id=remediation.scan_id if remediation else None,
                            remediation_id=(
                                remediation.id
                                if remediation
                                else snapshot.remediation_id
                            ),
                            playbook_id=Path(playbook).stem,
                            phase_id=phase_id,
                            event_type="snapshot_process",
                            evidence_category="snapshot",
                            severity=(
                                Severity.INFO
                                if process.returncode == 0
                                else Severity.HIGH
                            ),
                            status=(
                                "succeeded"
                                if process.returncode == 0
                                else "failed"
                            ),
                            return_code=process.returncode,
                            stdout=output[:65536],
                            raw_output=json.dumps(safe_payload),
                            source="ansible-playbook",
                            remediation_relevance="execution",
                        ),
                        host,
                    )
                ]
            return process.returncode == 0, redact_text(output[:131072], host), events
        finally:
            try:
                if vars_path.exists():
                    vars_path.write_bytes(b"\x00" * vars_path.stat().st_size)
                    vars_path.unlink()
            finally:
                event_path.unlink(missing_ok=True)


def parse_snapshot_callback_events(
    path: Path,
    host: Host,
) -> List[StructuredLogEvent]:
    events: List[StructuredLogEvent] = []
    if not path.exists():
        return events
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = StructuredLogEvent.model_validate_json(line)
            events.append(sanitize_log_event(event, host))
        except Exception:
            continue
    return events


def snapshot_event(
    host: Host,
    remediation: Optional[Remediation],
    job_id: str,
    phase_id: str,
    status: str,
    summary: str,
    snapshot: Optional[RollbackSnapshot] = None,
    external_snapshot_id: Optional[str] = None,
) -> StructuredLogEvent:
    return sanitize_log_event(
        StructuredLogEvent(
            id="log-%s" % uuid4().hex[:12],
            timestamp=utc_now(),
            host_id=host.id,
            job_id=job_id or None,
            scan_id=remediation.scan_id if remediation else None,
            remediation_id=remediation.id if remediation else (
                snapshot.remediation_id if snapshot else None
            ),
            playbook_id="simulated-snapshot",
            phase_id=phase_id,
            task_id="snapshot.%s" % phase_id,
            event_type="snapshot_operation",
            evidence_category="snapshot",
            severity=Severity.INFO if status == "succeeded" else Severity.HIGH,
            status=status,
            stdout=summary,
            source="simulated-snapshot",
            simulated=True,
            remediation_relevance="execution",
            correlation_ids={
                "job_id": job_id,
                "remediation_id": (
                    remediation.id if remediation else (
                        snapshot.remediation_id if snapshot else ""
                    )
                ),
                "rollback_snapshot_id": snapshot.id if snapshot else "",
                "external_snapshot_id": external_snapshot_id
                or (snapshot.external_snapshot_id if snapshot else ""),
            },
        ),
        host,
    )


def parse_external_snapshot_id(output: str) -> Optional[str]:
    for line in output.splitlines():
        if line.startswith("external_snapshot_id="):
            return line.split("=", 1)[1].strip() or None
    return None


def parse_health_checks(output: str) -> Dict[str, str]:
    checks: Dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("health_check."):
            continue
        key, _, value = line.partition("=")
        checks[key.replace("health_check.", "")] = value.strip()
    return checks
