#!/usr/bin/env python3
"""Central fail-closed redaction for P2 persisted and serialized evidence."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, Mapping

_AUTHORIZATION = re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|HMAC_KEY|AUTH)[A-Z0-9_]*\s*[:=]\s*)[^\s,;]+"
)
_SECRET_FLAG = re.compile(
    r"(?i)(--(?:token|secret|password|api-key|hmac-key|authorization)(?:=|\s+))[^\s]+"
)
_EMBEDDED_PRIVATE_PATH = re.compile(r"(?<![A-Za-z0-9])(?:/home|/mnt|/tmp)/[^\s,;\]\[(){}]+")


def redact_text(value: str, *, secrets: Iterable[str] = ()) -> str:
    redacted: str = str(value)
    safe_secrets: list[str] = list({str(item) for item in secrets if item})
    safe_secrets.sort(key=lambda item: len(item), reverse=True)
    for secret in safe_secrets:
        redacted = redacted.replace(secret, "<redacted-secret>")
    redacted = _AUTHORIZATION.sub(r"\1<redacted-secret>", redacted)
    redacted = _SECRET_ASSIGNMENT.sub(r"\1<redacted-secret>", redacted)
    redacted = _SECRET_FLAG.sub(r"\1<redacted-secret>", redacted)
    if redacted.startswith(("/home/", "/mnt/", "/tmp/")) and " " not in redacted:
        return f"<private-path>/{Path(redacted).name}"
    return _EMBEDDED_PRIVATE_PATH.sub("<private-path>", redacted)


def redact_value(value: Any, *, secrets: Iterable[str] = ()) -> Any:
    if isinstance(value, str):
        return redact_text(value, secrets=secrets)
    if isinstance(value, Mapping):
        return {
            str(key): redact_value(item, secrets=secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item, secrets=secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, secrets=secrets) for item in value)
    return value


def redact_error_text(value: str) -> str:
    """Persist only an allowlisted exception class, never caller/child details."""
    prefix = value.split(":", 1)[0]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,80}", prefix):
        prefix = "OperationError"
    return f"{prefix}: operation failed (details redacted)"
