from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Tuple

from .credentials import CredentialVault
from .models import (
    ExecutionPhase,
    ExecutionResult,
    Host,
    Remediation,
)


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
    async def execute(self, host: Host, remediation: Remediation) -> ExecutionResult:
        raise NotImplementedError


class SimulatedExecutor(RemediationExecutor):
    async def execute(self, host: Host, remediation: Remediation) -> ExecutionResult:
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
                summary="%s package updates were simulated." % remediation.update_scope.title(),
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
                    summary="Approved reboot was simulated and host connectivity returned.",
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
        return ExecutionResult(
            success=True,
            summary="Simulation completed. No host was changed.",
            changed=True,
            reboot_performed=reboot,
            phases=phases,
        )


class AnsibleExecutor(RemediationExecutor):
    def __init__(self, playbook_dir: Path, vault: CredentialVault) -> None:
        self.playbook_dir = playbook_dir
        self.vault = vault

    async def execute(self, host: Host, remediation: Remediation) -> ExecutionResult:
        phases: List[ExecutionPhase] = []
        changed = False
        reboot_performed = False

        for phase_name, catalog_key in (
            ("pre_patch_check", "preflight"),
            ("package_upgrade", remediation.update_scope),
            ("reboot_required_check", "reboot_check"),
        ):
            success, output = await self._run_playbook(host, PLAYBOOK_CATALOG[catalog_key])
            phases.append(
                ExecutionPhase(
                    name=phase_name,
                    state="succeeded" if success else "failed",
                    summary="%s %s." % (phase_name, "passed" if success else "failed"),
                    output=output,
                    changed="changed=1" in output,
                )
            )
            changed = changed or "changed=1" in output
            if not success:
                return await self._failure(host, phases, changed, phase_name)

        reboot_required = (
            "reboot_required=true" in phases[-1].output.lower()
            or remediation.reboot_assessment.status == "required"
        )
        if reboot_required:
            success, output = await self._run_playbook(host, PLAYBOOK_CATALOG["reboot"])
            phases.append(
                ExecutionPhase(
                    name="reboot",
                    state="succeeded" if success else "failed",
                    summary="Approved reboot %s." % ("completed" if success else "failed"),
                    output=output,
                    changed=success,
                )
            )
            changed = True
            reboot_performed = success
            if not success:
                return await self._failure(host, phases, changed, "reboot")

        success, output = await self._run_playbook(host, PLAYBOOK_CATALOG["validate"])
        phases.append(
            ExecutionPhase(
                name="post_patch_validation",
                state="succeeded" if success else "failed",
                summary="Post-patch validation %s." % ("passed" if success else "failed"),
                output=output,
            )
        )
        if not success:
            return await self._failure(host, phases, changed, "post_patch_validation")

        return ExecutionResult(
            success=True,
            summary="Ansible patch workflow completed and validation passed.",
            changed=changed,
            reboot_performed=reboot_performed,
            phases=phases,
        )

    async def _failure(
        self,
        host: Host,
        phases: List[ExecutionPhase],
        changed: bool,
        failed_phase: str,
    ) -> ExecutionResult:
        recovery_success, recovery_output = await self._run_playbook(
            host, PLAYBOOK_CATALOG["recovery"]
        )
        phases.append(
            ExecutionPhase(
                name="predefined_recovery",
                state="succeeded" if recovery_success else "failed",
                summary="Recovery diagnostics were collected.",
                output=recovery_output,
            )
        )
        return ExecutionResult(
            success=False,
            summary="Execution stopped after %s failed." % failed_phase,
            changed=changed,
            reboot_performed=False,
            phases=phases,
            failure_actions_taken=[
                "remaining campaign hosts stopped",
                "operator notification recorded",
                "predefined recovery diagnostics attempted",
            ],
        )

    async def _run_playbook(self, host: Host, playbook: str) -> Tuple[bool, str]:
        key_path = self.vault.key_path(host.credential_id)
        if key_path is None:
            return False, "A valid uploaded SSH credential is required."
        process = await asyncio.create_subprocess_exec(
            "ansible-playbook",
            "-i",
            "%s," % host.address,
            str(self.playbook_dir / playbook),
            "-u",
            host.username,
            "--private-key",
            str(key_path),
            "-e",
            "ansible_port=%s" % host.port,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        output = "\n".join(
            value.decode(errors="replace").strip()
            for value in (stdout, stderr)
            if value
        )
        return process.returncode == 0, output
