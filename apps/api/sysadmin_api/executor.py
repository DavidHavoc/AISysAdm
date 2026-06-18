from __future__ import annotations

import asyncio
import json
import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Tuple
from uuid import uuid4

from .credentials import CredentialService
from .models import (
    ExecutionPhase,
    ExecutionResult,
    Host,
    Remediation,
    Severity,
    StructuredLogEvent,
    utc_now,
)
from .ssh_utils import scan_host_key, temporary_known_hosts


PLAYBOOK_CATALOG = {
    "preflight": "pre-patch-check.yml",
    "security": "security-upgrade.yml",
    "all": "full-upgrade.yml",
    "reboot_check": "reboot-required-check.yml",
    "reboot": "reboot.yml",
    "validate": "post-patch-validation.yml",
    "recovery": "recovery-diagnostics.yml",
}


class RemediationExecutor(ABC):
    @abstractmethod
    async def execute(
        self,
        host: Host,
        remediation: Remediation,
        job_id: str = "",
    ) -> ExecutionResult:
        raise NotImplementedError


class SimulatedExecutor(RemediationExecutor):
    async def execute(
        self,
        host: Host,
        remediation: Remediation,
        job_id: str = "",
    ) -> ExecutionResult:
        guard_error = approval_guard(host, remediation)
        if guard_error:
            return failure_result(guard_error)
        reboot = remediation.reboot_assessment.status in (
            "required",
            "required_after_patch",
        )
        phases = [
            ExecutionPhase(
                name="pre_patch_check",
                state="succeeded",
                summary="Disk, package manager, and service baseline checks passed.",
            ),
            ExecutionPhase(
                name="package_upgrade",
                state="succeeded",
                summary="%s package updates were simulated."
                % remediation.update_scope.title(),
                changed=True,
            ),
            ExecutionPhase(
                name="reboot_required_check",
                state="succeeded",
                summary="Post-patch reboot check completed.",
            ),
        ]
        if reboot:
            phases.append(
                ExecutionPhase(
                    name="reboot",
                    state="succeeded",
                    summary="Approved reboot was simulated and connectivity returned.",
                    changed=True,
                )
            )
        phases.append(
            ExecutionPhase(
                name="post_patch_validation",
                state="succeeded",
                summary="Package and service validation passed.",
            )
        )
        events = [
            StructuredLogEvent(
                id="log-%s" % uuid4().hex[:12],
                timestamp=utc_now(),
                host_id=host.id,
                job_id=job_id or None,
                scan_id=remediation.scan_id,
                remediation_id=remediation.id,
                playbook_id="simulation",
                phase_id=phase.name,
                task_id="simulation.%s" % phase.name,
                event_type="ansible_task",
                evidence_category="remediation",
                severity=Severity.INFO,
                status=phase.state,
                changed=phase.changed,
                source="simulated-ansible",
                simulated=True,
                reboot_relevance="required" if phase.name == "reboot" else "none",
                remediation_relevance="execution",
                correlation_ids={
                    "job_id": job_id,
                    "remediation_id": remediation.id,
                },
            )
            for phase in phases
        ]
        return ExecutionResult(
            success=True,
            summary="Simulation completed. No host was changed.",
            changed=True,
            reboot_performed=reboot,
            phases=phases,
            events=events,
        )


class AnsibleExecutor(RemediationExecutor):
    def __init__(
        self,
        playbook_dir: Path,
        callback_dir: Path,
        credentials: CredentialService,
    ) -> None:
        self.playbook_dir = playbook_dir
        self.callback_dir = callback_dir
        self.credentials = credentials

    async def execute(
        self,
        host: Host,
        remediation: Remediation,
        job_id: str = "",
    ) -> ExecutionResult:
        guard_error = approval_guard(host, remediation)
        if guard_error:
            return failure_result(guard_error)
        if not host.ssh_host_key_fingerprint:
            return failure_result("SSH host key has not been confirmed")
        known_line, fingerprint = await scan_host_key(host.address, host.port)
        if fingerprint != host.ssh_host_key_fingerprint:
            return failure_result("SSH host key changed; execution blocked")

        phases: List[ExecutionPhase] = []
        events: List[StructuredLogEvent] = []
        changed = False
        reboot_performed = False
        with self.credentials.temporary_key(host.credential_id) as key_path:
            with temporary_known_hosts(known_line) as known_hosts:
                for phase_name, catalog_key in (
                    ("pre_patch_check", "preflight"),
                    ("package_upgrade", remediation.update_scope),
                    ("reboot_required_check", "reboot_check"),
                ):
                    success, output, phase_events = await self._run_playbook(
                        host,
                        remediation,
                        job_id,
                        phase_name,
                        PLAYBOOK_CATALOG[catalog_key],
                        str(key_path),
                        str(known_hosts),
                    )
                    events.extend(phase_events)
                    phase_changed = any(event.changed for event in phase_events)
                    phases.append(
                        ExecutionPhase(
                            name=phase_name,
                            state="succeeded" if success else "failed",
                            summary="%s %s."
                            % (phase_name, "passed" if success else "failed"),
                            output=output,
                            changed=phase_changed,
                        )
                    )
                    changed = changed or phase_changed
                    if not success:
                        return await self._failure(
                            host,
                            remediation,
                            job_id,
                            phases,
                            events,
                            changed,
                            phase_name,
                            str(key_path),
                            str(known_hosts),
                        )

                reboot_required = (
                    any(
                        "reboot_required=true" in event.stdout.lower()
                        for event in events
                    )
                    or remediation.reboot_assessment.status == "required"
                )
                if reboot_required:
                    if (
                        host.patch_policy.reboot_policy == "never"
                        or not remediation.reboot_assessment.approved_if_required
                    ):
                        return await self._failure(
                            host,
                            remediation,
                            job_id,
                            phases,
                            events,
                            changed,
                            "reboot_approval_guard",
                            str(key_path),
                            str(known_hosts),
                        )
                    success, output, phase_events = await self._run_playbook(
                        host,
                        remediation,
                        job_id,
                        "reboot",
                        PLAYBOOK_CATALOG["reboot"],
                        str(key_path),
                        str(known_hosts),
                    )
                    events.extend(phase_events)
                    phases.append(
                        ExecutionPhase(
                            name="reboot",
                            state="succeeded" if success else "failed",
                            summary="Approved reboot %s."
                            % ("completed" if success else "failed"),
                            output=output,
                            changed=success,
                        )
                    )
                    changed = True
                    reboot_performed = success
                    if not success:
                        return await self._failure(
                            host,
                            remediation,
                            job_id,
                            phases,
                            events,
                            changed,
                            "reboot",
                            str(key_path),
                            str(known_hosts),
                        )

                success, output, phase_events = await self._run_playbook(
                    host,
                    remediation,
                    job_id,
                    "post_patch_validation",
                    PLAYBOOK_CATALOG["validate"],
                    str(key_path),
                    str(known_hosts),
                )
                events.extend(phase_events)
                phases.append(
                    ExecutionPhase(
                        name="post_patch_validation",
                        state="succeeded" if success else "failed",
                        summary="Post-patch validation %s."
                        % ("passed" if success else "failed"),
                        output=output,
                    )
                )
                if not success:
                    return await self._failure(
                        host,
                        remediation,
                        job_id,
                        phases,
                        events,
                        changed,
                        "post_patch_validation",
                        str(key_path),
                        str(known_hosts),
                    )

        return ExecutionResult(
            success=True,
            summary="Ansible patch workflow completed and validation passed.",
            changed=changed,
            reboot_performed=reboot_performed,
            phases=phases,
            events=events,
        )

    async def _failure(
        self,
        host: Host,
        remediation: Remediation,
        job_id: str,
        phases: List[ExecutionPhase],
        events: List[StructuredLogEvent],
        changed: bool,
        failed_phase: str,
        key_path: str,
        known_hosts_path: str,
    ) -> ExecutionResult:
        success, output, recovery_events = await self._run_playbook(
            host,
            remediation,
            job_id,
            "predefined_recovery",
            PLAYBOOK_CATALOG["recovery"],
            key_path,
            known_hosts_path,
        )
        events.extend(recovery_events)
        phases.append(
            ExecutionPhase(
                name="predefined_recovery",
                state="succeeded" if success else "failed",
                summary="Recovery diagnostics were collected.",
                output=output,
            )
        )
        return ExecutionResult(
            success=False,
            summary="Execution stopped after %s failed." % failed_phase,
            changed=changed,
            reboot_performed=False,
            phases=phases,
            events=events,
            failure_actions_taken=[
                "remaining campaign hosts stopped",
                "operator alert recorded",
                "predefined recovery diagnostics attempted",
            ],
        )

    async def _run_playbook(
        self,
        host: Host,
        remediation: Remediation,
        job_id: str,
        phase_id: str,
        playbook: str,
        key_path: str,
        known_hosts_path: str,
    ) -> Tuple[bool, str, List[StructuredLogEvent]]:
        descriptor, event_path_raw = tempfile.mkstemp(prefix="ai-sysadm-events-", suffix=".jsonl")
        os.close(descriptor)
        event_path = Path(event_path_raw)
        environment = os.environ.copy()
        environment.update(
            {
                "ANSIBLE_CALLBACK_PLUGINS": str(self.callback_dir),
                "ANSIBLE_CALLBACKS_ENABLED": "ai_jsonl",
                "AI_SYSADM_EVENT_FILE": str(event_path),
                "AI_SYSADM_JOB_ID": job_id,
                "AI_SYSADM_HOST_ID": host.id,
                "AI_SYSADM_SCAN_ID": remediation.scan_id or "",
                "AI_SYSADM_REMEDIATION_ID": remediation.id,
                "AI_SYSADM_PHASE_ID": phase_id,
                "AI_SYSADM_PLAYBOOK_ID": Path(playbook).stem,
            }
        )
        process = await asyncio.create_subprocess_exec(
            "ansible-playbook",
            "-i",
            "%s," % host.address,
            str(self.playbook_dir / playbook),
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
        events = parse_callback_events(event_path)
        event_path.unlink(missing_ok=True)
        if not events:
            events.append(
                StructuredLogEvent(
                    id="log-%s" % uuid4().hex[:12],
                    timestamp=utc_now(),
                    host_id=host.id,
                    job_id=job_id or None,
                    scan_id=remediation.scan_id,
                    remediation_id=remediation.id,
                    playbook_id=Path(playbook).stem,
                    phase_id=phase_id,
                    event_type="ansible_process",
                    evidence_category="remediation",
                    severity=Severity.INFO if process.returncode == 0 else Severity.HIGH,
                    status="succeeded" if process.returncode == 0 else "failed",
                    return_code=process.returncode,
                    stdout=stdout.decode(errors="replace")[:65536],
                    stderr=stderr.decode(errors="replace")[:65536],
                    raw_output=output[:131072],
                    source="ansible-playbook",
                    remediation_relevance="execution",
                )
            )
        return process.returncode == 0, output, events


def parse_callback_events(path: Path) -> List[StructuredLogEvent]:
    events: List[StructuredLogEvent] = []
    if not path.exists():
        return events
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            events.append(StructuredLogEvent.model_validate_json(line))
        except Exception:
            continue
    return events


def failure_result(summary: str) -> ExecutionResult:
    return ExecutionResult(
        success=False,
        summary=summary,
        changed=False,
        reboot_performed=False,
        phases=[],
        events=[],
        failure_actions_taken=["operator alert recorded"],
    )


def approval_guard(host: Host, remediation: Remediation) -> str:
    if remediation.approval_state != "approved":
        return "Execution blocked because the remediation is not approved"
    if remediation.approval_scope != "patch_and_reboot_if_required":
        return "Execution blocked because the approval scope is invalid"
    if not remediation.approved_by or not remediation.approved_at:
        return "Execution blocked because approval metadata is incomplete"
    if (
        remediation.reboot_assessment.status != "not_expected"
        and not remediation.reboot_assessment.approved_if_required
    ):
        return "Execution blocked because required reboot scope is not approved"
    if (
        host.patch_policy.reboot_policy == "never"
        and remediation.reboot_assessment.status != "not_expected"
    ):
        return "Execution blocked because host policy forbids reboot risk"
    return ""
