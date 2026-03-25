from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from enum import Enum
from typing import Any


def sanitize_text(
    value: str | None,
    *,
    max_length: int | None = None,
    single_line: bool = False,
) -> str | None:
    if value is None:
        return None
    cleaned = value.replace("\x00", "")
    if single_line:
        cleaned = " ".join(cleaned.split())
    if max_length is not None and max_length > 0 and len(cleaned) > max_length:
        suffix = "..."
        head_length = max(0, max_length - len(suffix))
        cleaned = f"{cleaned[:head_length]}{suffix}"
    return cleaned


def sanitize_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value) or ""
    if isinstance(value, Enum):
        return sanitize_json_value(value.value)
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            sanitize_text(str(key)) or str(key): sanitize_json_value(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [sanitize_json_value(item) for item in value]
    if isinstance(value, set):
        return [sanitize_json_value(item) for item in sorted(value, key=str)]
    return value
