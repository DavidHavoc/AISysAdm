from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from typing import Dict, List

from .credentials import CredentialVault
from .models import (
    Host,
    HostLogs,
    HostSnapshot,
    PackageSummary,
    PackageUpdate,
    ServiceSummary,
    SystemSummary,
    utc_now,
)


READ_ONLY_COMMANDS: Dict[str, str] = {
    "os_release": "cat /etc/os-release",
    "upgradable_packages": "apt list --upgradable 2>/dev/null",
    "reboot_required": "test -f /var/run/reboot-required && cat /var/run/reboot-required || true",
    "failed_units": "systemctl --failed --no-legend --plain || true",
    "uptime": "cat /proc/uptime",
    "load_average": "cat /proc/loadavg",
    "disk_root": "df -P / | tail -1",
    "memory": "free -m",
    "kernel": "uname -r",
    "journal": "journalctl -p warning -n 200 --no-pager || true",
    "auth": "journalctl -u ssh -u sshd -n 100 --no-pager || true",
    "apt_history": "tail -n 200 /var/log/apt/history.log 2>/dev/null || true",
}


class HostCollector(ABC):
    @abstractmethod
    async def collect(self, host: Host) -> HostSnapshot:
        raise NotImplementedError


class DemoCollector(HostCollector):
    async def collect(self, host: Host) -> HostSnapshot:
        updates = [
            PackageUpdate(
                name="linux-image-generic",
                current_version="6.8.0.31",
                candidate_version="6.8.0.40",
                security_update=True,
                reboot_hint=True,
            ),
            PackageUpdate(
                name="openssl",
                current_version="3.0.1",
                candidate_version="3.0.2",
                security_update=True,
            ),
            PackageUpdate(
                name="curl",
                current_version="8.5.0",
                candidate_version="8.5.1",
            ),
        ]
        return HostSnapshot(
            host_id=host.id,
            collected_at=utc_now(),
            commands={
                "upgradable_packages": "\n".join(
                    "%s/%s [upgradable from: %s]"
                    % (item.name, item.candidate_version, item.current_version)
                    for item in updates
                ),
                "failed_units": "nginx.service loaded failed failed",
                "reboot_required": "",
            },
            package_summary=PackageSummary(
                pending_security_updates=2,
                pending_package_updates=3,
                reboot_required_now=False,
                updates=updates,
            ),
            service_summary=ServiceSummary(failed_units=["nginx.service"]),
            system_summary=SystemSummary(
                uptime_hours=340,
                load_average=[0.41, 0.52, 0.49],
                disk_usage_percent=81,
                memory_usage_percent=67,
                kernel_version="6.8.0-31-generic",
            ),
            logs=HostLogs(
                journal=(
                    "nginx[123]: failed to bind to 0.0.0.0:80\n"
                    "systemd[1]: nginx.service: Failed with result 'exit-code'."
                ),
                auth="sshd[991]: Accepted publickey for ubuntu from 10.0.0.8",
                apt_history="Upgrade: libc6:amd64 (2.39-0ubuntu8, 2.39-0ubuntu8.1)",
            ),
        )


class SshCollector(HostCollector):
    def __init__(self, vault: CredentialVault) -> None:
        self.vault = vault

    async def collect(self, host: Host) -> HostSnapshot:
        key_path = self.vault.key_path(host.credential_id)
        if key_path is None:
            raise RuntimeError("A valid uploaded SSH credential is required for SSH collection")

        outputs: Dict[str, str] = {}
        for name, command in READ_ONLY_COMMANDS.items():
            outputs[name] = await self._run(host, str(key_path), command)
        return normalize_snapshot(host, outputs)

    async def _run(self, host: Host, key_path: str, command: str) -> str:
        process = await asyncio.create_subprocess_exec(
            "ssh",
            "-i",
            key_path,
            "-p",
            str(host.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "%s@%s" % (host.username, host.address),
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(
                "SSH collection failed for %s: %s"
                % (host.name, stderr.decode(errors="replace").strip())
            )
        return stdout.decode(errors="replace").strip()


def normalize_snapshot(host: Host, outputs: Dict[str, str]) -> HostSnapshot:
    updates = parse_updates(outputs.get("upgradable_packages", ""))
    failed_units = [
        line.split()[0]
        for line in outputs.get("failed_units", "").splitlines()
        if line.strip() and line.split()
    ]
    uptime_text = outputs.get("uptime", "0").split()
    uptime_hours = float(uptime_text[0]) / 3600 if uptime_text else 0
    load_parts = outputs.get("load_average", "0 0 0").split()[:3]
    loads = [float(value) for value in load_parts]
    while len(loads) < 3:
        loads.append(0)

    disk_match = re.search(r"(\d+)%", outputs.get("disk_root", ""))
    memory_usage = parse_memory_usage(outputs.get("memory", ""))
    reboot_now = bool(outputs.get("reboot_required", "").strip())
    return HostSnapshot(
        host_id=host.id,
        collected_at=utc_now(),
        commands=outputs,
        package_summary=PackageSummary(
            pending_security_updates=sum(1 for item in updates if item.security_update),
            pending_package_updates=len(updates),
            reboot_required_now=reboot_now,
            updates=updates,
        ),
        service_summary=ServiceSummary(failed_units=failed_units),
        system_summary=SystemSummary(
            uptime_hours=uptime_hours,
            load_average=loads,
            disk_usage_percent=float(disk_match.group(1)) if disk_match else 0,
            memory_usage_percent=memory_usage,
            kernel_version=outputs.get("kernel", "unknown"),
        ),
        logs=HostLogs(
            journal=outputs.get("journal", ""),
            auth=outputs.get("auth", ""),
            apt_history=outputs.get("apt_history", ""),
        ),
    )


def parse_updates(output: str) -> List[PackageUpdate]:
    updates: List[PackageUpdate] = []
    reboot_prefixes = ("linux-", "libc6", "systemd", "dbus")
    for line in output.splitlines():
        if not line or line.startswith("Listing"):
            continue
        match = re.match(r"([^/]+)/([^\s]+).*\[upgradable from: ([^\]]+)\]", line)
        if not match:
            continue
        name, candidate, current = match.groups()
        lowered = line.lower()
        updates.append(
            PackageUpdate(
                name=name,
                current_version=current,
                candidate_version=candidate,
                security_update="security" in lowered,
                reboot_hint=name.startswith(reboot_prefixes),
            )
        )
    return updates


def parse_memory_usage(output: str) -> float:
    for line in output.splitlines():
        if line.lower().startswith("mem:"):
            parts = line.split()
            if len(parts) >= 3 and float(parts[1]) > 0:
                return round(float(parts[2]) / float(parts[1]) * 100, 1)
    return 0
