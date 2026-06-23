from __future__ import annotations

from typing import Any

from app.services.agent.execution_registry import AgentActionExecutorContext, AgentExecutionResult, execute_registered_action
from app.services.agent.tool_rbac import require_tool_rbac


class AgentExecutionService:
    def __init__(self, *, supported_action_types: set[str]) -> None:
        self.supported_action_types = supported_action_types

    def execute(
        self,
        context: AgentActionExecutorContext,
        *,
        action: dict[str, Any],
    ) -> AgentExecutionResult:
        return self._execute_authorized(context, action=action)

    @require_tool_rbac(
        role_getter=lambda _self, context, *, action: context.session_user_role,
        action_getter=lambda _self, _context, *, action: action,
    )
    def _execute_authorized(
        self,
        context: AgentActionExecutorContext,
        *,
        action: dict[str, Any],
    ) -> AgentExecutionResult:
        return execute_registered_action(
            context,
            action=action,
            supported_action_types=self.supported_action_types,
        )
