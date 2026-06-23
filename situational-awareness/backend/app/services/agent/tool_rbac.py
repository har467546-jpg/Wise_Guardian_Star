from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any, TypeVar

from app.services.haor.action_policy import is_action_allowed_for_role
from app.utils.sanitize import sanitize_text


F = TypeVar("F", bound=Callable[..., Any])


class ToolRbacError(PermissionError):
    def __init__(self, action_type: str, role: str) -> None:
        self.action_type = action_type
        self.role = role
        super().__init__(f"当前角色 {role or 'unknown'} 无权执行动作 {action_type or 'unknown'}")


@dataclass(frozen=True, slots=True)
class ToolRbacDecision:
    allowed: bool
    action_type: str
    role: str
    reason: str | None = None


def normalize_role(role: Any) -> str:
    value = getattr(role, "value", role)
    return sanitize_text(str(value or ""), max_length=32, single_line=True) or ""


def evaluate_tool_rbac(action: dict[str, Any], *, role: Any) -> ToolRbacDecision:
    action_type = sanitize_text(str((action if isinstance(action, dict) else {}).get("action_type") or ""), max_length=64, single_line=True) or ""
    normalized_role = normalize_role(role)
    allowed = is_action_allowed_for_role(action_type, normalized_role)
    return ToolRbacDecision(
        allowed=allowed,
        action_type=action_type,
        role=normalized_role,
        reason=None if allowed else f"角色 {normalized_role or 'unknown'} 不允许执行 {action_type or 'unknown'}",
    )


def require_tool_rbac(*, role_getter: Callable[..., Any], action_getter: Callable[..., dict[str, Any]]) -> Callable[[F], F]:
    def _decorator(func: F) -> F:
        @wraps(func)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            decision = evaluate_tool_rbac(action_getter(*args, **kwargs), role=role_getter(*args, **kwargs))
            if not decision.allowed:
                raise ToolRbacError(decision.action_type, decision.role)
            return func(*args, **kwargs)

        return _wrapped  # type: ignore[return-value]

    return _decorator
