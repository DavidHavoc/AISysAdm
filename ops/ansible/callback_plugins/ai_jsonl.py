from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ansible.plugins.callback import CallbackBase


DOCUMENTATION = r"""
callback: ai_jsonl
type: aggregate
short_description: Write bounded AI Sysadmin task events as JSONL
version_added: "2.15"
requirements:
  - AI_SYSADM_EVENT_FILE environment variable
"""


SENSITIVE_KEYS = {
    "password",
    "passwd",
    "private_key",
    "secret",
    "token",
    "authorization",
}
TASK_PATTERN = re.compile(r"^\[([a-zA-Z0-9_.-]+)\]\s*(.*)$")
MAX_FIELD_BYTES = 65536


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "ai_jsonl"
    CALLBACK_NEEDS_WHITELIST = False

    def __init__(self):
        super().__init__()
        self.event_file = os.environ.get("AI_SYSADM_EVENT_FILE")
        self.started = {}

    def v2_playbook_on_task_start(self, task, is_conditional):
        self.started[str(task._uuid)] = time.monotonic()

    def v2_runner_on_ok(self, result):
        self._record(result, "succeeded")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record(result, "failed")

    def v2_runner_on_unreachable(self, result):
        self._record(result, "unreachable")

    def v2_runner_on_skipped(self, result):
        self._record(result, "skipped")

    def v2_runner_retry(self, result):
        self._record(result, "retrying")

    def _record(self, result, status):
        if not self.event_file:
            return
        task_name = result._task.get_name().strip()
        match = TASK_PATTERN.match(task_name)
        task_id = match.group(1) if match else str(result._task._uuid)
        readable_name = match.group(2) if match else task_name
        raw = sanitize(result._result)
        stdout, stdout_meta = bounded(raw.get("stdout", ""))
        stderr, stderr_meta = bounded(raw.get("stderr", raw.get("msg", "")))
        duration_ms = int(
            (
                time.monotonic()
                - self.started.get(str(result._task._uuid), time.monotonic())
            )
            * 1000
        )
        severity = "high" if status in ("failed", "unreachable") else "info"
        event = {
            "id": "log-%s" % uuid4().hex[:12],
            "schema_version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": duration_ms,
            "host_id": os.environ.get("AI_SYSADM_HOST_ID") or None,
            "job_id": os.environ.get("AI_SYSADM_JOB_ID") or None,
            "scan_id": os.environ.get("AI_SYSADM_SCAN_ID") or None,
            "remediation_id": os.environ.get("AI_SYSADM_REMEDIATION_ID") or None,
            "playbook_id": os.environ.get("AI_SYSADM_PLAYBOOK_ID") or None,
            "phase_id": os.environ.get("AI_SYSADM_PHASE_ID") or None,
            "task_id": task_id,
            "event_type": "ansible_task",
            "evidence_category": evidence_category(task_id),
            "severity": severity,
            "status": status,
            "changed": bool(raw.get("changed", False)),
            "return_code": raw.get("rc"),
            "retry_count": int(raw.get("attempts", 1)) - 1,
            "failure_classification": classify_failure(status, stderr),
            "command_description": readable_name,
            "before_value": raw.get("before"),
            "after_value": raw.get("after"),
            "stdout": stdout,
            "stderr": stderr,
            "raw_output": json.dumps(raw, default=str)[:131072],
            "source": str(getattr(result._task, "action", "ansible")),
            "truncated": stdout_meta["truncated"] or stderr_meta["truncated"],
            "original_bytes": stdout_meta["original_bytes"]
            + stderr_meta["original_bytes"],
            "redacted": True,
            "simulated": False,
            "externally_processed": False,
            "reboot_relevance": (
                "required"
                if "reboot" in task_id
                else "none"
            ),
            "remediation_relevance": (
                "execution"
                if os.environ.get("AI_SYSADM_REMEDIATION_ID")
                else "diagnostic"
            ),
            "correlation_ids": {
                "ansible_host": result._host.get_name(),
                "task_uuid": str(result._task._uuid),
            },
        }
        path = Path(self.event_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, separators=(",", ":"), default=str))
            handle.write("\n")


def sanitize(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if any(token in key.lower() for token in SENSITIVE_KEYS)
            else sanitize(item)
            for key, item in value.items()
            if key != "invocation"
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        value = re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "[IP_ADDRESS]",
            value,
        )
        return value
    return value


def bounded(value):
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    encoded = text.encode("utf-8", errors="replace")
    retained = encoded[:MAX_FIELD_BYTES]
    return (
        retained.decode("utf-8", errors="replace"),
        {
            "truncated": len(encoded) > len(retained),
            "original_bytes": len(encoded),
        },
    )


def evidence_category(task_id):
    parts = task_id.split(".")
    return parts[1] if len(parts) > 1 else "remediation"


def classify_failure(status, stderr):
    if status == "unreachable":
        return "ssh_unreachable"
    lowered = stderr.lower()
    if "permission denied" in lowered:
        return "permission_denied"
    if "lock" in lowered and ("apt" in lowered or "dpkg" in lowered):
        return "package_manager_locked"
    if status == "failed":
        return "task_failed"
    return None
