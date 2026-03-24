from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from app.db.models.enums import TaskExecutionStatus


AgentSessionStatus = Literal["active", "waiting_approval", "running", "completed", "failed"]
AgentRole = Literal["system", "user", "assistant"]
AgentMessageType = Literal["text", "clarifying", "plan", "task_update", "action_update", "error"]
AgentWriteActionType = Literal[
    "create_discovery_job",
    "verify_asset_risks",
    "install_runner",
    "create_or_resume_remediation_session",
    "approve_remediation_session",
]
AgentUIActionType = Literal[
    "navigate",
    "click",
    "input",
    "select",
    "toggle",
    "expand",
    "scroll_into_view",
    "submit",
    "wait_for",
]
AgentStreamClientType = Literal["hello", "message", "ui_step", "approve_plan", "ping"]
AgentStreamServerType = Literal[
    "session_snapshot",
    "agent_state",
    "turn_started",
    "action_update",
    "assistant_message_start",
    "assistant_message_delta",
    "assistant_message_done",
    "ui_actions_requested",
    "plan_pending",
    "task_update",
    "error",
    "turn_done",
]


class AgentPageContextRead(BaseModel):
    pathname: str = "/"
    query: dict[str, Any] = Field(default_factory=dict)
    asset_id: str | None = None
    finding_id: str | None = None
    task_id: str | None = None


class AgentBrowserDOMNodeRead(BaseModel):
    node_id: str
    tag_name: str
    role: str | None = None
    text: str | None = None
    label: str | None = None
    href: str | None = None
    value: str | None = None
    is_interactive: bool = False
    is_visible: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)


class AgentBrowserVisibleActionRead(BaseModel):
    action_id: str
    action_type: AgentUIActionType | str = "click"
    node_id: str | None = None
    label: str
    description: str | None = None


class AgentBrowserSemanticEntityRead(BaseModel):
    kind: str
    id: str | None = None
    label: str | None = None
    status: str | None = None
    source: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class AgentBrowserSemanticSectionRead(BaseModel):
    section_id: str
    label: str
    node_id: str | None = None
    description: str | None = None


class AgentBrowserSemanticActionRead(BaseModel):
    semantic_action_id: str
    label: str
    action_type: AgentUIActionType | str = "click"
    node_id: str | None = None
    description: str | None = None
    section_id: str | None = None
    href: str | None = None
    selector: str | None = None
    text_contains: str | None = None
    target_entity: dict[str, Any] = Field(default_factory=dict)
    keywords: list[str] = Field(default_factory=list)


class AgentBrowserSemanticFormRead(BaseModel):
    semantic_form_id: str
    label: str
    node_id: str | None = None
    fields: list[dict[str, Any]] = Field(default_factory=list)
    submit_action_id: str | None = None


class AgentSemanticPageContextRead(BaseModel):
    page_kind: str = "unknown"
    primary_entity: dict[str, Any] = Field(default_factory=dict)
    secondary_entities: list[dict[str, Any]] = Field(default_factory=list)
    visible_sections: list[AgentBrowserSemanticSectionRead] = Field(default_factory=list)
    semantic_actions: list[AgentBrowserSemanticActionRead] = Field(default_factory=list)
    semantic_forms: list[AgentBrowserSemanticFormRead] = Field(default_factory=list)
    active_dialog: dict[str, Any] = Field(default_factory=dict)
    selected_rows: list[dict[str, Any]] = Field(default_factory=list)
    summary: str | None = None


class AgentBrowserContextSummaryRead(BaseModel):
    page_kind: str = "unknown"
    primary_entity: dict[str, Any] = Field(default_factory=dict)
    secondary_entities: list[dict[str, Any]] = Field(default_factory=list)
    visible_sections: list[dict[str, Any]] = Field(default_factory=list)
    top_semantic_actions: list[dict[str, Any]] = Field(default_factory=list)
    selected_rows: list[dict[str, Any]] = Field(default_factory=list)
    active_dialog: dict[str, Any] = Field(default_factory=dict)
    has_modal_or_drawer: bool = False
    summary: str | None = None


class AgentBrowserContextRead(BaseModel):
    pathname: str = "/"
    origin: str | None = None
    title: str | None = None
    query: dict[str, Any] = Field(default_factory=dict)
    asset_id: str | None = None
    finding_id: str | None = None
    task_id: str | None = None
    selected_entities: list[dict[str, Any]] = Field(default_factory=list)
    open_panels: list[dict[str, Any]] = Field(default_factory=list)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    visible_actions: list[AgentBrowserVisibleActionRead] = Field(default_factory=list)
    semantic_page_context: AgentSemanticPageContextRead = Field(default_factory=AgentSemanticPageContextRead)
    semantic_actions: list[AgentBrowserSemanticActionRead] = Field(default_factory=list)
    semantic_forms: list[AgentBrowserSemanticFormRead] = Field(default_factory=list)
    summary_json: AgentBrowserContextSummaryRead = Field(default_factory=AgentBrowserContextSummaryRead)
    dom_snapshot: list[AgentBrowserDOMNodeRead] = Field(default_factory=list)


class AgentUIActionRead(BaseModel):
    action_id: str
    action_type: AgentUIActionType | str
    semantic_action_id: str | None = None
    target_node_id: str | None = None
    selector: str | None = None
    text_contains: str | None = None
    label_contains: str | None = None
    href: str | None = None
    value: str | None = None
    field_name: str | None = None
    option_label: str | None = None
    wait_ms: int | None = None
    rationale: str | None = None
    expected_outcome: str | None = None
    expected_page_kind: str | None = None
    expected_section: str | None = None
    expected_entity: dict[str, Any] = Field(default_factory=dict)
    retryable: bool | None = True


class AgentUIActionResultRead(BaseModel):
    action_id: str
    action_type: AgentUIActionType | str
    ok: bool
    semantic_action_id: str | None = None
    target_node_id: str | None = None
    resolved_node_id: str | None = None
    message: str | None = None
    resolved_target: dict[str, Any] = Field(default_factory=dict)
    attempt_count: int | None = None
    detail_json: dict[str, Any] = Field(default_factory=dict)


class AgentSuggestedReplyRead(BaseModel):
    label: str
    text: str


class AgentProposedActionRead(BaseModel):
    action_type: AgentWriteActionType
    title: str
    reason: str
    params: dict[str, Any] = Field(default_factory=dict)


class AgentMessageRead(BaseModel):
    id: str
    role: AgentRole
    message_type: AgentMessageType | str
    content: str
    payload_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    suggested_replies: list[AgentSuggestedReplyRead] = Field(default_factory=list)
    proposed_write_actions: list[AgentProposedActionRead] = Field(default_factory=list)


class AgentSessionRead(BaseModel):
    session_id: str
    agent_id: str
    status: AgentSessionStatus | str
    route_context_json: dict[str, Any] = Field(default_factory=dict)
    working_context_json: dict[str, Any] = Field(default_factory=dict)
    dialog_state_json: dict[str, Any] = Field(default_factory=dict)
    pending_plan_json: dict[str, Any] = Field(default_factory=dict)
    browser_runtime_json: dict[str, Any] = Field(default_factory=dict)
    agent_state_json: dict[str, Any] = Field(default_factory=dict)
    last_task_id: str | None = None
    messages: list[AgentMessageRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class AgentMessageCreateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_message_id: str | None = Field(default=None, max_length=128)
    content: str = Field(min_length=1, max_length=4000)
    page_context: AgentPageContextRead = Field(
        default_factory=AgentPageContextRead,
        validation_alias=AliasChoices("page_context", "route_context"),
    )
    browser_context: AgentBrowserContextRead = Field(default_factory=AgentBrowserContextRead)


class AgentUIStepRequest(BaseModel):
    step_request_id: str | None = Field(default=None, max_length=128)
    browser_context: AgentBrowserContextRead = Field(default_factory=AgentBrowserContextRead)
    ui_action_results: list[AgentUIActionResultRead] = Field(default_factory=list)


class AgentApprovalRequest(BaseModel):
    note: str | None = Field(default=None, max_length=500)


class AgentApprovalResponse(BaseModel):
    session_id: str
    task_id: str
    status: TaskExecutionStatus


class AgentStreamClientEnvelope(BaseModel):
    type: AgentStreamClientType
    client_message_id: str | None = Field(default=None, max_length=128)
    step_request_id: str | None = Field(default=None, max_length=128)
    content: str | None = Field(default=None, max_length=4000)
    note: str | None = Field(default=None, max_length=500)
    page_context: AgentPageContextRead = Field(default_factory=AgentPageContextRead)
    browser_context: AgentBrowserContextRead = Field(default_factory=AgentBrowserContextRead)
    ui_action_results: list[AgentUIActionResultRead] = Field(default_factory=list)


class AgentSessionSnapshotEvent(BaseModel):
    type: Literal["session_snapshot"] = "session_snapshot"
    session: AgentSessionRead


class AgentStateEvent(BaseModel):
    type: Literal["agent_state"] = "agent_state"
    agent_state_json: dict[str, Any] = Field(default_factory=dict)
    turn_id: str | None = None


class AgentTurnStartedEvent(BaseModel):
    type: Literal["turn_started"] = "turn_started"
    turn_id: str
    phase: Literal["message", "ui_step", "approve"]
    client_message_id: str | None = None


class AgentAssistantMessageStartEvent(BaseModel):
    type: Literal["assistant_message_start"] = "assistant_message_start"
    turn_id: str
    message_type: AgentMessageType | str = "text"


class AgentAssistantDeltaEvent(BaseModel):
    type: Literal["assistant_message_delta"] = "assistant_message_delta"
    turn_id: str
    delta: str


class AgentAssistantMessageDoneEvent(BaseModel):
    type: Literal["assistant_message_done"] = "assistant_message_done"
    turn_id: str
    message: AgentMessageRead


class AgentActionUpdateEvent(BaseModel):
    type: Literal["action_update"] = "action_update"
    turn_id: str
    content: str
    message: AgentMessageRead | None = None
    trace: dict[str, Any] = Field(default_factory=dict)


class AgentUIActionsRequestedEvent(BaseModel):
    type: Literal["ui_actions_requested"] = "ui_actions_requested"
    turn_id: str
    ui_actions: list[AgentUIActionRead] = Field(default_factory=list)
    content: str | None = None


class AgentPlanPendingEvent(BaseModel):
    type: Literal["plan_pending"] = "plan_pending"
    turn_id: str
    message: AgentMessageRead
    pending_plan_json: dict[str, Any] = Field(default_factory=dict)


class AgentTaskUpdateEvent(BaseModel):
    type: Literal["task_update"] = "task_update"
    task_id: str
    status: TaskExecutionStatus | str
    progress: int | None = None
    message: str | None = None


class AgentErrorEvent(BaseModel):
    type: Literal["error"] = "error"
    detail: str
    turn_id: str | None = None
    status_code: int | None = None
    message: AgentMessageRead | None = None


class AgentTurnDoneEvent(BaseModel):
    type: Literal["turn_done"] = "turn_done"
    turn_id: str
    status: str
