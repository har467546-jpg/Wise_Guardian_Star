from __future__ import annotations

from typing import Any

from app.services.agent.execution_registry import AgentActionExecutorContext, AgentExecutionResult, execute_registered_action


class AgentExecutionService:
    def __init__(self, *, supported_action_types: set[str]) -> None:
        self.supported_action_types = supported_action_types

    def execute(
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
