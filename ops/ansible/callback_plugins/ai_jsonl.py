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
    "passphrase",
    "private_key",
    "secret",
    "token",
    "authorization",
    "api_key",
    "access_key",
    "client_secret",
    "email",
    "username",
    "hostname",
    "address",
}
TASK_PATTERN = re.compile(r"^\[([a-zA-Z0-9_.-]+)\]\s*(.*)$")
MAX_FIELD_BYTES = 65536
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
AUTHORIZATION_HEADER_PATTERN = re.compile(
    r"(?i)\bauthorization\b\s*([:=])\s*(?:bearer|basic|token)?\s*[^\s,;]+"
)
BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\b"
    r"\s*([:=])\s*(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
IDENTITY_KEY_VALUE_PATTERN = re.compile(
    r"(?i)\b(hostname|host|user|username|login|address)\b"
    r"\s*([:=])\s*(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
API_KEY_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)


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
        raw, raw_meta = sanitize(result._result)
        stdout, stdout_meta = bounded(raw.get("stdout", ""))
        stderr, stderr_meta = bounded(raw.get("stderr", raw.get("msg", "")))
        raw_output, _ = bounded(raw)
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
            "raw_output": raw_output[:131072],
            "source": str(getattr(result._task, "action", "ansible")),
            "truncated": stdout_meta["truncated"] or stderr_meta["truncated"],
            "original_bytes": stdout_meta["original_bytes"]
            + stderr_meta["original_bytes"],
            "redacted": raw_meta["applied"] or raw_meta["safe"],
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


def placeholder_for_key(key):
    lowered = key.lower()
    if any(token in lowered for token in ("private_key", "private-key", "ssh_key")):
        return "[PRIVATE_KEY]"
    if "authorization" in lowered or lowered == "auth_header":
        return "[AUTHORIZATION]"
    if "bearer" in lowered and "token" in lowered:
        return "[BEARER_TOKEN]"
    if any(token in lowered for token in ("password", "passwd", "passphrase")):
        return "[PASSWORD]"
    if "api_key" in lowered or lowered == "apikey":
        return "[API_KEY]"
    if "access_key" in lowered:
        return "[API_KEY]"
    if "client_secret" in lowered or lowered == "secret":
        return "[SECRET]"
    if lowered == "token" or lowered.endswith("_token"):
        return "[TOKEN]"
    if "email" in lowered:
        return "[EMAIL]"
    if lowered in {"username", "user", "login"} or lowered.endswith("_username"):
        return "[USERNAME]"
    if "hostname" in lowered or lowered.endswith("_hostname") or lowered == "host_name":
        return "[HOSTNAME]"
    if "address" in lowered or lowered in {"ip", "ip_address"}:
        return "[ADDRESS]"
    return "[REDACTED]"


def preserve_quotes(value, placeholder):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return "%s%s%s" % (value[0], placeholder, value[0])
    return placeholder


def replace_key_value_secret(match):
    key = match.group(1)
    separator = match.group(2)
    raw_value = match.group(3)
    placeholder = placeholder_for_key(key)
    return "%s%s%s" % (key, separator, preserve_quotes(raw_value, placeholder))


def replace_identity_key_value(match):
    key = match.group(1)
    separator = match.group(2)
    raw_value = match.group(3)
    placeholder = {
        "hostname": "[HOSTNAME]",
        "host": "[HOSTNAME]",
        "user": "[USERNAME]",
        "username": "[USERNAME]",
        "login": "[USERNAME]",
        "address": "[ADDRESS]",
    }.get(key.lower(), "[REDACTED]")
    return "%s%s%s" % (key, separator, preserve_quotes(raw_value, placeholder))


def sanitize_string(value):
    redacted = value
    redacted = PRIVATE_KEY_PATTERN.sub("[PRIVATE_KEY]", redacted)
    redacted = AUTHORIZATION_HEADER_PATTERN.sub(
        lambda match: "Authorization%s [AUTHORIZATION]" % match.group(1),
        redacted,
    )
    redacted = BEARER_TOKEN_PATTERN.sub("Bearer [BEARER_TOKEN]", redacted)
    redacted = KEY_VALUE_SECRET_PATTERN.sub(replace_key_value_secret, redacted)
    redacted = IDENTITY_KEY_VALUE_PATTERN.sub(replace_identity_key_value, redacted)
    for pattern in API_KEY_PATTERNS:
        redacted = pattern.sub("[API_KEY]", redacted)
    redacted = EMAIL_PATTERN.sub("[EMAIL]", redacted)
    redacted = IP_PATTERN.sub("[IP_ADDRESS]", redacted)
    applied = redacted != value
    return redacted, applied, (not applied and string_is_safe(value))


def string_is_safe(value):
    if PRIVATE_KEY_PATTERN.search(value):
        return False
    if AUTHORIZATION_HEADER_PATTERN.search(value):
        return False
    if BEARER_TOKEN_PATTERN.search(value):
        return False
    if KEY_VALUE_SECRET_PATTERN.search(value):
        return False
    if IDENTITY_KEY_VALUE_PATTERN.search(value):
        return False
    if EMAIL_PATTERN.search(value):
        return False
    if IP_PATTERN.search(value):
        return False
    return not any(pattern.search(value) for pattern in API_KEY_PATTERNS)


def sanitize(value):
    if isinstance(value, dict):
        sanitized = {}
        applied = False
        safe = True
        for key, item in value.items():
            if key == "invocation":
                continue
            if any(token in key.lower() for token in SENSITIVE_KEYS) and item is not None:
                sanitized[key] = placeholder_for_key(key)
                applied = True
                continue
            rendered, item_applied, item_safe = sanitize(item)
            sanitized[key] = rendered
            applied = applied or item_applied
            safe = safe and item_safe
        return sanitized, applied, safe
    if isinstance(value, list):
        sanitized = []
        applied = False
        safe = True
        for item in value:
            rendered, item_applied, item_safe = sanitize(item)
            sanitized.append(rendered)
            applied = applied or item_applied
            safe = safe and item_safe
        return sanitized, applied, safe
    if isinstance(value, str):
        return sanitize_string(value)
    return value, False, True


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
