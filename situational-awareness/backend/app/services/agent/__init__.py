from .state_machine import (
    ACTIVE_PUBLIC_SESSION_STATUSES,
    AgentRuntimeState,
    get_runtime_state,
    is_active_public_session_status,
    set_runtime_state,
    set_runtime_state_from_internal,
)
from .context_service import sanitize_browser_context_summary
from .session_service import (
    append_interrupted_task_message,
    ensure_active_session,
    has_interrupted_task_message,
    interrupt_agent_session,
    load_recent_session,
    mark_agent_session_interrupted,
    reconcile_running_session_state,
    reset_agent_session,
    restore_session_from_running_state,
)

_LAZY_EXPORTS = {
    "ACTION_EXECUTORS",
    "AgentActionExecutorContext",
    "AgentExecutionResult",
    "execute_registered_action",
}

__all__ = [
    "ACTIVE_PUBLIC_SESSION_STATUSES",
    "ACTION_EXECUTORS",
    "AgentActionExecutorContext",
    "AgentExecutionResult",
    "AgentRuntimeState",
    "append_interrupted_task_message",
    "ensure_active_session",
    "execute_registered_action",
    "get_runtime_state",
    "has_interrupted_task_message",
    "interrupt_agent_session",
    "is_active_public_session_status",
    "load_recent_session",
    "mark_agent_session_interrupted",
    "reconcile_running_session_state",
    "reset_agent_session",
    "restore_session_from_running_state",
    "sanitize_browser_context_summary",
    "set_runtime_state",
    "set_runtime_state_from_internal",
]


def __getattr__(name: str):
    if name in _LAZY_EXPORTS:
        from . import execution_registry

        return getattr(execution_registry, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
