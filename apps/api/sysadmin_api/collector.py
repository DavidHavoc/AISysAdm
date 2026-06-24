from __future__ import annotations

import asyncio
import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Tuple
from uuid import uuid4

from .credentials import CredentialService
from .models import (
    ConnectionTestResult,
    EvidenceState,
    Host,
    HostLogs,
    HostSnapshot,
    NetworkSummary,
    PackageSummary,
    PackageUpdate,
    ServiceSummary,
    Severity,
    StructuredLogEvent,
    SystemSummary,
    utc_now,
)
from .redaction import redact_text, sanitize_log_event
from .ssh_utils import scan_host_key, temporary_known_hosts


READ_ONLY_COMMANDS: Dict[str, str] = {
    "os_release": "cat /etc/os-release",
    "kernel": "uname -r",
    "boot_id": "cat /proc/sys/kernel/random/boot_id",
    "uptime": "cat /proc/uptime",
    "reboot_required": "test -f /var/run/reboot-required && cat /var/run/reboot-required || true",
    "reboot_history": "last -x reboot shutdown -n 20 2>/dev/null || true",
    "cpu": "LC_ALL=C lscpu 2>/dev/null || cat /proc/cpuinfo",
    "load_average": "cat /proc/loadavg",
    "disk_root": "df -P / | tail -1",
    "inode_root": "df -Pi / | tail -1",
    "filesystems": "df -PT -x tmpfs -x devtmpfs",
    "mounts": "findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS",
    "readonly_mounts": "findmnt -rn -o TARGET,OPTIONS | awk '$2 ~ /(^|,)ro(,|$)/ {print}'",
    "memory": "free -m",
    "upgradable_packages": "apt list --upgradable 2>/dev/null",
    "held_packages": "apt-mark showhold 2>/dev/null || true",
    "package_audit": "dpkg --audit 2>&1 || true",
    "apt_locks": "for f in /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do fuser \"$f\" 2>/dev/null && echo \"$f locked\"; done || true",
    "failed_units": "systemctl --failed --no-legend --plain || true",
    "restarting_units": "systemctl list-units --state=activating,deactivating,reloading --no-legend --plain || true",
    "system_state": "systemctl is-system-running 2>/dev/null || true",
    "recent_unit_changes": "journalctl --since '-24 hours' -u '*.service' -p notice -n 500 --no-pager || true",
    "journal": "journalctl --since '-24 hours' -p warning -n 1000 --no-pager || true",
    "kernel_journal": "journalctl --since '-24 hours' -k -p warning -n 1000 --no-pager || true",
    "kernel_critical": "journalctl --since '-24 hours' -k --no-pager | grep -Ei 'oom|out of memory|i/o error|filesystem error|ext4-fs error|xfs.*error|hardware error' | tail -n 500 || true",
    "auth": "journalctl --since '-24 hours' -u ssh -u sshd -t sudo -n 1000 --no-pager || true",
    "apt_history": "tail -n 1000 /var/log/apt/history.log 2>/dev/null || true",
    "interfaces": "ip -brief address 2>/dev/null || true",
    "routes": "ip route show 2>/dev/null || true",
    "dns": "grep -E '^nameserver' /etc/resolv.conf 2>/dev/null || true",
    "listening_ports": "ss -lntupH 2>/dev/null || true",
    "failed_network_units": "systemctl --failed --no-legend --plain 'systemd-networkd*' 'NetworkManager*' 'networking*' 2>/dev/null || true",
    "users": "getent passwd | awk -F: '$3 >= 1000 {print $1 \":\" $3 \":\" $7}'",
    "sudo_posture": "grep -RhsE '^[^#].*(ALL|NOPASSWD)' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed -E 's/^[^ ]+/[USER]/' | head -n 200 || true",
}


@dataclass
class CollectionResult:
    snapshot: HostSnapshot
    events: List[StructuredLogEvent]


class HostCollector(ABC):
    @abstractmethod
    async def collect(
        self,
        host: Host,
        job_id: str = "",
        scan_id: str = "",
    ) -> CollectionResult:
        raise NotImplementedError

    @abstractmethod
    async def test_connection(self, host: Host) -> ConnectionTestResult:
        raise NotImplementedError


class DemoCollector(HostCollector):
    async def collect(
        self,
        host: Host,
        job_id: str = "",
        scan_id: str = "",
    ) -> CollectionResult:
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
        commands = {
            "upgradable_packages": "\n".join(
                "%s/%s [upgradable from: %s]"
                % (item.name, item.candidate_version, item.current_version)
                for item in updates
            ),
            "failed_units": "nginx.service loaded failed failed",
            "reboot_required": "",
            "held_packages": "",
            "journal": "nginx.service failed to bind and exited",
            "kernel_journal": "",
            "auth": "Accepted publickey for [USERNAME] from [IP_ADDRESS]",
        }
        now = utc_now()
        snapshot = HostSnapshot(
            id="snapshot-%s" % uuid4().hex[:12],
            host_id=host.id,
            collected_at=now,
            commands=commands,
            evidence_states={
                key: EvidenceState(
                    original_bytes=len(value.encode("utf-8")),
                    retained_bytes=len(value.encode("utf-8")),
                )
                for key, value in commands.items()
            },
            package_summary=PackageSummary(
                pending_security_updates=2,
                pending_package_updates=3,
                reboot_required_now=False,
                updates=updates,
            ),
            service_summary=ServiceSummary(
                failed_units=["nginx.service"],
                degraded=True,
            ),
            system_summary=SystemSummary(
                uptime_hours=340,
                load_average=[0.41, 0.52, 0.49],
                disk_usage_percent=81,
                inode_usage_percent=22,
                memory_usage_percent=67,
                kernel_version="6.8.0-31-generic",
                boot_id="demo-boot-id",
            ),
            network_summary=NetworkSummary(
                interfaces=["eth0 UP [ADDRESS]"],
                default_routes=["default via [ADDRESS]"],
                dns_servers=["[ADDRESS]"],
                listening_ports=["tcp LISTEN 0.0.0.0:22"],
            ),
            logs=HostLogs(
                journal="nginx.service failed to bind and exited",
                kernel="",
                auth="Accepted publickey for [USERNAME] from [IP_ADDRESS]",
                apt_history="Upgrade: libc6",
                reboot_history="reboot system boot",
            ),
        )
        snapshot.snapshot_hash = snapshot_digest(snapshot)
        events = [
            collection_event(
                host,
                key,
                value,
                snapshot.evidence_states[key],
                job_id,
                scan_id,
                simulated=True,
            )
            for key, value in commands.items()
        ]
        return CollectionResult(snapshot=snapshot, events=events)

    async def test_connection(self, host: Host) -> ConnectionTestResult:
        return ConnectionTestResult(
            success=True,
            ssh_reachable=True,
            sudo_available=True,
            os_supported=True,
            ansible_compatible=True,
            host_key_fingerprint="SHA256:demo-host-key",
            checks={"mode": "simulation"},
        )


class SshCollector(HostCollector):
    def __init__(
        self,
        credentials: CredentialService,
        max_bytes_per_source: int = 65536,
    ) -> None:
        self.credentials = credentials
        self.max_bytes_per_source = max_bytes_per_source

    async def collect(
        self,
        host: Host,
        job_id: str = "",
        scan_id: str = "",
    ) -> CollectionResult:
        if not host.ssh_host_key_fingerprint:
            raise RuntimeError("SSH host key must be confirmed before collection")
        known_line, fingerprint = await scan_host_key(host.address, host.port)
        if fingerprint != host.ssh_host_key_fingerprint:
            raise RuntimeError("SSH host key fingerprint changed; collection blocked")

        outputs: Dict[str, str] = {}
        states: Dict[str, EvidenceState] = {}
        events: List[StructuredLogEvent] = []
        with self.credentials.temporary_key(host.credential_id) as key_path:
            with temporary_known_hosts(known_line) as known_hosts:
                for name, command in READ_ONLY_COMMANDS.items():
                    output, state = await self._run(
                        host,
                        str(key_path),
                        str(known_hosts),
                        command,
                    )
                    if name in ("auth", "users", "sudo_posture", "interfaces", "routes", "dns"):
                        output = redact_text(output, host)
                    outputs[name] = output
                    states[name] = state
                    events.append(
                        collection_event(
                            host,
                            name,
                            output,
                            state,
                            job_id,
                            scan_id,
                        )
                    )
        snapshot = normalize_snapshot(host, outputs, states)
        return CollectionResult(snapshot=snapshot, events=events)

    async def test_connection(self, host: Host) -> ConnectionTestResult:
        checks: Dict[str, str] = {}
        try:
            known_line, fingerprint = await scan_host_key(host.address, host.port)
            checks["host_key"] = "available"
        except Exception as error:
            return ConnectionTestResult(
                success=False,
                ssh_reachable=False,
                sudo_available=False,
                os_supported=False,
                ansible_compatible=False,
                checks={"host_key": redact_text(str(error), host)},
            )
        try:
            with self.credentials.temporary_key(host.credential_id) as key_path:
                with temporary_known_hosts(known_line) as known_hosts:
                    os_output, _ = await self._run(
                        host,
                        str(key_path),
                        str(known_hosts),
                        "cat /etc/os-release",
                    )
                    sudo_output, sudo_state = await self._run(
                        host,
                        str(key_path),
                        str(known_hosts),
                        "sudo -n true && echo sudo_ok",
                    )
            os_supported = any(
                marker in os_output.lower()
                for marker in ("id=ubuntu", "id=debian", "id_like=debian")
            )
            sudo_available = "sudo_ok" in sudo_output and sudo_state.status == "available"
            checks.update(
                {
                    "ssh": "reachable",
                    "sudo": "available" if sudo_available else sudo_state.status,
                    "os": "supported" if os_supported else "unsupported",
                }
            )
            return ConnectionTestResult(
                success=os_supported and sudo_available,
                ssh_reachable=True,
                sudo_available=sudo_available,
                os_supported=os_supported,
                ansible_compatible=True,
                host_key_fingerprint=fingerprint,
                checks=checks,
            )
        except Exception as error:
            checks["ssh"] = redact_text(str(error), host)
            return ConnectionTestResult(
                success=False,
                ssh_reachable=False,
                sudo_available=False,
                os_supported=False,
                ansible_compatible=False,
                host_key_fingerprint=fingerprint,
                checks=checks,
            )

    async def _run(
        self,
        host: Host,
        key_path: str,
        known_hosts_path: str,
        command: str,
    ) -> Tuple[str, EvidenceState]:
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
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=%s" % known_hosts_path,
            "%s@%s" % (host.username, host.address),
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        combined = stdout
        status = "available"
        reason = None
        if process.returncode != 0:
            error_text = stderr.decode(errors="replace").strip()
            if "permission denied" in error_text.lower():
                status = "permission_denied"
            else:
                status = "unavailable"
            reason = error_text[:500]
            combined = stdout + b"\n" + stderr
        original_bytes = len(combined)
        retained = combined[: self.max_bytes_per_source]
        truncated = original_bytes > len(retained)
        if truncated and status == "available":
            status = "truncated"
        return (
            retained.decode(errors="replace").strip(),
            EvidenceState(
                status=status,
                original_bytes=original_bytes,
                retained_bytes=len(retained),
                truncated=truncated,
                reason=reason,
            ),
        )


def normalize_snapshot(
    host: Host,
    outputs: Dict[str, str],
    states: Dict[str, EvidenceState],
) -> HostSnapshot:
    updates = parse_updates(outputs.get("upgradable_packages", ""))
    failed_units = first_columns(outputs.get("failed_units", ""))
    restarting_units = first_columns(outputs.get("restarting_units", ""))
    uptime_text = outputs.get("uptime", "0").split()
    uptime_hours = float(uptime_text[0]) / 3600 if uptime_text else 0
    load_parts = outputs.get("load_average", "0 0 0").split()[:3]
    loads = [float(value) for value in load_parts if is_float(value)]
    while len(loads) < 3:
        loads.append(0)

    snapshot = HostSnapshot(
        id="snapshot-%s" % uuid4().hex[:12],
        host_id=host.id,
        collected_at=utc_now(),
        commands=outputs,
        evidence_states=states,
        package_summary=PackageSummary(
            pending_security_updates=sum(1 for item in updates if item.security_update),
            pending_package_updates=len(updates),
            reboot_required_now=bool(outputs.get("reboot_required", "").strip()),
            held_packages=[
                line.strip()
                for line in outputs.get("held_packages", "").splitlines()
                if line.strip()
            ],
            updates=updates,
        ),
        service_summary=ServiceSummary(
            failed_units=failed_units,
            restarting_units=restarting_units,
            degraded=outputs.get("system_state", "").strip() not in ("running", ""),
        ),
        system_summary=SystemSummary(
            uptime_hours=uptime_hours,
            load_average=loads,
            disk_usage_percent=parse_percent(outputs.get("disk_root", "")),
            inode_usage_percent=parse_percent(outputs.get("inode_root", "")),
            memory_usage_percent=parse_memory_usage(outputs.get("memory", "")),
            kernel_version=outputs.get("kernel", "unknown"),
            boot_id=outputs.get("boot_id", "unknown"),
        ),
        network_summary=NetworkSummary(
            interfaces=bounded_lines(outputs.get("interfaces", ""), 200),
            default_routes=bounded_lines(outputs.get("routes", ""), 200),
            dns_servers=bounded_lines(outputs.get("dns", ""), 50),
            listening_ports=bounded_lines(outputs.get("listening_ports", ""), 500),
        ),
        logs=HostLogs(
            journal=outputs.get("journal", ""),
            kernel="\n".join(
                filter(
                    None,
                    (
                        outputs.get("kernel_journal", ""),
                        outputs.get("kernel_critical", ""),
                    ),
                )
            ),
            auth=outputs.get("auth", ""),
            apt_history=outputs.get("apt_history", ""),
            reboot_history=outputs.get("reboot_history", ""),
        ),
    )
    snapshot.snapshot_hash = snapshot_digest(snapshot)
    return snapshot


def snapshot_digest(snapshot: HostSnapshot) -> str:
    payload = snapshot.model_dump(mode="json")
    payload.pop("snapshot_hash", None)
    payload.pop("collected_at", None)
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def collection_event(
    host: Host,
    source_name: str,
    output: str,
    state: EvidenceState,
    job_id: str,
    scan_id: str,
    simulated: bool = False,
) -> StructuredLogEvent:
    severity = (
        Severity.MEDIUM
        if state.status in ("missing", "unavailable", "permission_denied", "truncated")
        else Severity.INFO
    )
    return sanitize_log_event(
        StructuredLogEvent(
        id="log-%s" % uuid4().hex[:12],
        timestamp=utc_now(),
        host_id=host.id,
        job_id=job_id or None,
        scan_id=scan_id or None,
        event_type="evidence_collected",
        evidence_category=source_name,
        severity=severity,
        status=state.status,
        stdout=output,
        source="ssh:%s" % source_name,
        truncated=state.truncated,
        original_bytes=state.original_bytes,
        simulated=simulated,
        remediation_relevance="diagnostic",
        correlation_ids={"host_id": host.id, "scan_id": scan_id},
        ),
        host,
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
        updates.append(
            PackageUpdate(
                name=name,
                current_version=current,
                candidate_version=candidate,
                security_update="security" in line.lower(),
                reboot_hint=name.startswith(reboot_prefixes),
            )
        )
    return updates


def parse_memory_usage(output: str) -> float:
    for line in output.splitlines():
        if line.lower().startswith("mem:"):
            parts = line.split()
            if len(parts) >= 3 and is_float(parts[1]) and float(parts[1]) > 0:
                return round(float(parts[2]) / float(parts[1]) * 100, 1)
    return 0


def parse_percent(output: str) -> float:
    match = re.search(r"(\d+)%", output)
    return float(match.group(1)) if match else 0


def first_columns(output: str) -> List[str]:
    return [
        line.split()[0]
        for line in output.splitlines()
        if line.strip() and line.split()
    ]


def bounded_lines(output: str, maximum: int) -> List[str]:
    return [line for line in output.splitlines() if line.strip()][:maximum]


def is_float(value: str) -> bool:
    try:
        float(value)
        return True
    except ValueError:
        return False
