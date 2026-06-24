from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

from .models import Host, StructuredLogEvent


EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
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


@dataclass(frozen=True)
class RedactionSummary:
    value: Any
    applied: bool
    verified_safe: bool


def _preserve_quotes(value: str, placeholder: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return "%s%s%s" % (value[0], placeholder, value[0])
    return placeholder


def _placeholder_for_key(key: str) -> Optional[str]:
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
    if (
        "address" in lowered
        or lowered in {"ip", "ip_address"}
        or lowered.endswith("_address")
    ):
        return "[ADDRESS]"
    return None


def _host_patterns(host: Optional[Host]) -> Iterable[Tuple[re.Pattern[str], str]]:
    if not host:
        return ()
    patterns = []
    for value, placeholder in (
        (host.name, "[HOSTNAME]"),
        (host.address, "[ADDRESS]"),
        (host.username, "[USERNAME]"),
    ):
        if not value:
            continue
        patterns.append(
            (
                re.compile(
                    r"(?<![A-Za-z0-9._-])%s(?![A-Za-z0-9._-])" % re.escape(value)
                ),
                placeholder,
            )
        )
    return patterns


def _replace_key_value_secret(match: re.Match[str]) -> str:
    key = match.group(1)
    separator = match.group(2)
    raw_value = match.group(3)
    placeholder = _placeholder_for_key(key) or "[REDACTED]"
    return "%s%s%s" % (key, separator, _preserve_quotes(raw_value, placeholder))


def _replace_identity_key_value(match: re.Match[str]) -> str:
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
    return "%s%s%s" % (key, separator, _preserve_quotes(raw_value, placeholder))


def _sanitize_string(value: str, host: Optional[Host]) -> RedactionSummary:
    redacted = value
    redacted = PRIVATE_KEY_PATTERN.sub("[PRIVATE_KEY]", redacted)
    redacted = AUTHORIZATION_HEADER_PATTERN.sub(
        lambda match: "Authorization%s [AUTHORIZATION]" % match.group(1),
        redacted,
    )
    redacted = BEARER_TOKEN_PATTERN.sub("Bearer [BEARER_TOKEN]", redacted)
    redacted = KEY_VALUE_SECRET_PATTERN.sub(_replace_key_value_secret, redacted)
    redacted = IDENTITY_KEY_VALUE_PATTERN.sub(_replace_identity_key_value, redacted)
    for pattern in API_KEY_PATTERNS:
        redacted = pattern.sub("[API_KEY]", redacted)
    redacted = EMAIL_PATTERN.sub("[EMAIL]", redacted)
    for pattern, replacement in _host_patterns(host):
        redacted = pattern.sub(replacement, redacted)
    redacted = IP_PATTERN.sub("[IP_ADDRESS]", redacted)
    applied = redacted != value
    return RedactionSummary(
        value=redacted,
        applied=applied,
        verified_safe=not applied and _string_is_safe(value, host),
    )


def _string_is_safe(value: str, host: Optional[Host]) -> bool:
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
    if any(pattern.search(value) for pattern in API_KEY_PATTERNS):
        return False
    return not any(pattern.search(value) for pattern, _ in _host_patterns(host))


def sanitize_text(value: str, host: Optional[Host] = None) -> RedactionSummary:
    return _sanitize_string(value, host)


def sanitize_value(
    value: Any,
    host: Optional[Host] = None,
) -> RedactionSummary:
    if isinstance(value, str):
        return _sanitize_string(value, host)
    if isinstance(value, list):
        sanitized = []
        applied = False
        safe = True
        for item in value:
            summary = sanitize_value(item, host)
            sanitized.append(summary.value)
            applied = applied or summary.applied
            safe = safe and summary.verified_safe
        return RedactionSummary(sanitized, applied, safe)
    if isinstance(value, dict):
        sanitized: Dict[Any, Any] = {}
        applied = False
        safe = True
        for key, item in value.items():
            placeholder = _placeholder_for_key(str(key))
            if placeholder and item is not None:
                sanitized[key] = placeholder
                applied = True
                continue
            summary = sanitize_value(item, host)
            sanitized[key] = summary.value
            applied = applied or summary.applied
            safe = safe and summary.verified_safe
        return RedactionSummary(sanitized, applied, safe)
    return RedactionSummary(value=value, applied=False, verified_safe=True)


def redact_text(value: str, host: Optional[Host] = None) -> str:
    return sanitize_text(value, host).value


def redact_payload(value: Any, host: Optional[Host] = None) -> Any:
    return sanitize_value(value, host).value


def sanitize_log_event(
    event: StructuredLogEvent,
    host: Optional[Host] = None,
) -> StructuredLogEvent:
    payload = {
        "before_value": event.before_value,
        "after_value": event.after_value,
        "stdout": event.stdout,
        "stderr": event.stderr,
        "raw_output": event.raw_output,
        "command_description": event.command_description,
        "source": event.source,
        "correlation_ids": event.correlation_ids,
    }
    summary = sanitize_value(payload, host)
    sanitized = event.model_copy(deep=True)
    sanitized.before_value = summary.value["before_value"]
    sanitized.after_value = summary.value["after_value"]
    sanitized.stdout = summary.value["stdout"]
    sanitized.stderr = summary.value["stderr"]
    sanitized.raw_output = summary.value["raw_output"]
    sanitized.command_description = summary.value["command_description"]
    sanitized.source = summary.value["source"]
    sanitized.correlation_ids = summary.value["correlation_ids"]
    sanitized.redacted = summary.applied or summary.verified_safe
    return sanitized


def sanitize_audit_details(
    details: Optional[Dict[str, Any]],
    host: Optional[Host] = None,
) -> Dict[str, Any]:
    value = details or {}
    summary = sanitize_value(value, host)
    return summary.value if isinstance(summary.value, dict) else {}


def sanitize_celery_payload(
    payload: Dict[str, Any],
    host: Optional[Host] = None,
) -> Dict[str, Any]:
    summary = sanitize_value(payload, host)
    return summary.value if isinstance(summary.value, dict) else {}


def compact_json(value: Dict[str, Any], max_tokens: int) -> str:
    text = json.dumps(value, separators=(",", ":"), sort_keys=True)
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 64] + '"__truncated_for_token_budget__":true}'
