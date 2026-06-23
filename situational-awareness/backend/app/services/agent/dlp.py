from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from app.utils.sanitize import sanitize_json_value, sanitize_text


SECRET_KEYWORDS = {
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "credentials",
    "key",
    "password",
    "passwd",
    "private_key",
    "secret",
    "ssh_key",
    "sudo_password",
    "token",
}

MASK = "[REDACTED]"
PRIVATE_KEY_MASK = "[REDACTED_PRIVATE_KEY]"

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?P<prefix>\b(?:api[_-]?key|authorization|bearer|client[_-]?secret|password|passwd|private[_-]?key|secret|sudo[_-]?password|token)\b\s*[:=]\s*)(?P<value>[^\s,;]+)",
    re.IGNORECASE,
)


def _is_secret_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key or "").strip().lower()).strip("_")
    if not normalized:
        return False
    if normalized in SECRET_KEYWORDS:
        return True
    return any(part in SECRET_KEYWORDS for part in normalized.split("_"))


def redact_sensitive_text(value: str | None, *, max_length: int | None = None, single_line: bool = False) -> str:
    text = sanitize_text(value, max_length=max_length, single_line=single_line) or ""
    if not text:
        return ""
    text = _PRIVATE_KEY_RE.sub(PRIVATE_KEY_MASK, text)
    text = _OPENAI_KEY_RE.sub(MASK, text)
    text = _JWT_RE.sub(MASK, text)
    text = _ASSIGNMENT_SECRET_RE.sub(lambda match: f"{match.group('prefix')}{MASK}", text)
    return text


def redact_sensitive_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = sanitize_text(str(key), single_line=True) or str(key)
            if _is_secret_key(normalized_key):
                redacted[normalized_key] = MASK if item not in (None, "") else item
            else:
                redacted[normalized_key] = redact_sensitive_payload(item)
        return sanitize_json_value(redacted)
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [redact_sensitive_payload(item) for item in value]
    return sanitize_json_value(value)


def build_dlp_summary(value: Any) -> dict[str, Any]:
    raw = sanitize_json_value(value)
    redacted = redact_sensitive_payload(raw)
    return {
        "redacted": raw != redacted,
        "strategy": "secrets_only",
    }
