from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.config import settings
from app.utils.sanitize import sanitize_text


@dataclass(frozen=True, slots=True)
class TerminalInputViolation:
    code: str
    message: str
    command_preview: str
    severity: str = "critical"


class TerminalInputFilter:
    def __init__(self) -> None:
        self._line_buffer = ""

    def inspect(self, data: str) -> TerminalInputViolation | None:
        if not getattr(settings, "SECURITY_TERMINAL_INPUT_FILTER_ENABLED", True):
            return None
        if not data:
            return None
        normalized = _normalize_control_chars(data)
        if _looks_dangerous(normalized):
            return _violation("dangerous_fragment", normalized)

        for char in normalized:
            if char in {"\r", "\n"}:
                line = self._line_buffer.strip()
                self._line_buffer = ""
                violation = _inspect_line(line)
                if violation is not None:
                    return violation
                continue
            if char == "\b" or char == "\x7f":
                self._line_buffer = self._line_buffer[:-1]
                continue
            self._line_buffer = (self._line_buffer + char)[-2000:]
        return None


def _inspect_line(line: str) -> TerminalInputViolation | None:
    normalized = sanitize_text(line, max_length=1000, single_line=True) or ""
    if not normalized:
        return None
    if _looks_dangerous(normalized):
        return _violation("dangerous_command", normalized)
    return None


def _looks_dangerous(value: str) -> bool:
    text = _canonicalize(value)
    patterns = (
        r"\brm\s+-[^\n;|&]*[rf]+[^\n;|&]*(?:/|\*)",
        r"\bcat\s+/etc/shadow\b",
        r"\b(?:curl|wget)\b[^\n]*(?:\|\s*(?:sh|bash|zsh)|\s+-O\s+-)",
        r"\bchmod\s+(?:777|666)\b",
        r"\bchown\s+-R\b[^\n]*(?:/|\*)",
        r"\bdd\s+if=/dev/(?:zero|random|urandom)\b",
        r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",
    )
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _canonicalize(value: str) -> str:
    text = _normalize_control_chars(value).lower()
    text = text.replace("\\ ", " ")
    text = re.sub(r"['\"]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _normalize_control_chars(value: str) -> str:
    return str(value or "").replace("\x1b", "")


def _violation(code: str, command: str) -> TerminalInputViolation:
    preview = sanitize_text(command, max_length=240, single_line=True) or ""
    return TerminalInputViolation(
        code=code,
        message="检测到高危终端命令，已实时阻断 SSH 会话",
        command_preview=preview,
    )
