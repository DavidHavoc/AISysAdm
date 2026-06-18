from __future__ import annotations

import json
import re
from typing import Any, Dict

from .models import Host


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def redact_text(value: str, host: Host) -> str:
    redacted = value
    replacements = {
        host.name: "[HOSTNAME]",
        host.address: "[ADDRESS]",
        host.username: "[USERNAME]",
    }
    for source, replacement in replacements.items():
        if source:
            redacted = redacted.replace(source, replacement)
    redacted = KEY_PATTERN.sub("[PRIVATE_KEY]", redacted)
    redacted = EMAIL_PATTERN.sub("[EMAIL]", redacted)
    redacted = IP_PATTERN.sub("[IP_ADDRESS]", redacted)
    return redacted


def redact_payload(value: Any, host: Host) -> Any:
    if isinstance(value, str):
        return redact_text(value, host)
    if isinstance(value, list):
        return [redact_payload(item, host) for item in value]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if any(token in key.lower() for token in ("password", "secret", "private_key"))
            else redact_payload(item, host)
            for key, item in value.items()
        }
    return value


def compact_json(value: Dict[str, Any], max_tokens: int) -> str:
    text = json.dumps(value, separators=(",", ":"), sort_keys=True)
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 64] + '"__truncated_for_token_budget__":true}'
