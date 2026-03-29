from __future__ import annotations

from datetime import UTC, datetime
import httpx
from types import SimpleNamespace

from app.db.models.agent_goal import AgentGoal
from app.db.models.enums import TaskExecutionStatus, TaskType
from app.schemas.agent import AgentMessageCreateRequest
from app.services import agent_playbook_service, haor_agent_service


class _FakeUnitDB:
    def add(self, value) -> None:
        if getattr(value, "id", None) is None:
            value.id = f"fake-{id(value)}"
        if getattr(value, "created_at", None) is None:
            value.created_at = datetime.now(UTC)

    def flush(self) -> None:
        return None


class _FakeLookupDB:
    def scalar(self, *_args, **_kwargs):
        return None

    def scalars(self, *_args, **_kwargs):
        return SimpleNamespace(unique=lambda: SimpleNamespace(all=lambda: []))


class _FakeRecoverDB:
    def __init__(self) -> None:
        self.committed = False
        self.refreshed: list[object] = []
        self.added: list[object] = []

    def add(self, value) -> None:
        self.added.append(value)

    def commit(self) -> None:
        self.committed = True

    def refresh(self, value) -> None:
        self.refreshed.append(value)

    def get(self, _model, _value):
        return None


class _FakeMessageDB(_FakeRecoverDB):
    def __init__(self, session) -> None:
        super().__init__()
        self.session = session

    def get(self, _model, value):
        if value == getattr(self.session, "id", None):
            return self.session
        return None

    def flush(self) -> None:
        return None


def test_build_model_request_uses_structured_messages() -> None:
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(role="user", message_type="text", content="帮我看看当前资产风险"),
            SimpleNamespace(role="assistant", message_type="clarifying", content="请告诉我是哪个资产"),
            SimpleNamespace(role="user", message_type="text", content="帮我继续分析这台资产"),
        ]
    )
    user = SimpleNamespace(role="admin")

    request = haor_agent_service._build_model_request(
        session=session,
        user=user,
        page_context={"pathname": "/assets", "query": {"assetId": "asset-1"}, "asset_id": "asset-1"},
        browser_context={"pathname": "/assets", "query": {"assetId": "asset-1"}, "asset_id": "asset-1"},
        browser_runtime={},
        working_context={
            "asset_id": "asset-1",
            "source": "page_reference",
            "summary": "资产 asset-1",
            "primary_target": {"asset_id": "asset-1", "source": "page_reference", "summary": "资产 asset-1"},
            "recent_targets": [{"asset_id": "asset-1", "source": "page_reference", "summary": "资产 asset-1"}],
        },
        dialog_state={
            "status": "awaiting_user_input",
            "intent_kind": "read_followup",
            "question_kind": "confirm",
            "intent_summary": "查看当前资产详情",
            "last_agent_question": "是否继续查看资产详情？",
            "expected_slots": [],
            "candidate_read_tools": [{"tool_name": "get_asset_detail", "arguments": {"asset_id": "asset-1"}}],
            "candidate_write_context": {},
            "targets_snapshot": {"working_context": {"asset_id": "asset-1"}},
        },
        followup_hint={"reply_kind": "affirm", "raw_user_reply": "继续", "pending_dialog_state": {"status": "awaiting_user_input"}},
        tool_traces=[{"tool_name": "get_asset_detail", "arguments": {"asset_id": "asset-1"}, "result": {"asset_id": "asset-1"}}],
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert request.messages[0].role == "system"
    assert "haor" in request.messages[0].text_content()
    assert request.messages[1].role == "system"
    assert "output_schema" in request.messages[1].text_content()
    assert '"conversation_focus"' in request.messages[2].text_content()
    assert '"recent_targets"' in request.messages[2].text_content()
    assert '"shared_working_context"' in request.messages[2].text_content()
    assert '"current_page_context"' in request.messages[2].text_content()
    assert '"pending_dialog_state"' in request.messages[2].text_content()
    assert '"followup_hint"' in request.messages[2].text_content()
    assert any("最近会话记录如下" in message.text_content() for message in request.messages if message.role == "user")
    assert any("assistant/clarifying: 请告诉我是哪个资产" in message.text_content() for message in request.messages if message.role == "user")
    assert any("当前用户问题：\n帮我继续分析这台资产" in message.text_content() for message in request.messages if message.role == "user")
    assert any('"executed_read_tools"' in message.text_content() for message in request.messages if message.role == "user")
    assert any("上一轮仍未完成的对话状态如下" in message.text_content() for message in request.messages if message.role == "user")


def test_build_model_request_serializes_datetime_tool_trace_context() -> None:
    base = datetime(2026, 3, 25, 2, 0, tzinfo=UTC)
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(role="user", message_type="text", content="继续"),
        ]
    )
    user = SimpleNamespace(role="admin")

    request = haor_agent_service._build_model_request(
        session=session,
        user=user,
        page_context={"pathname": "/tasks/task-1", "query": {}, "task_id": "task-1"},
        browser_context={"pathname": "/tasks/task-1", "query": {}, "task_id": "task-1"},
        browser_runtime={},
        working_context={
            "task_id": "task-1",
            "source": "task_watch",
            "summary": "任务 task-1",
            "primary_target": {"task_id": "task-1", "source": "task_watch", "summary": "任务 task-1"},
            "recent_targets": [{"task_id": "task-1", "source": "task_watch", "summary": "任务 task-1"}],
        },
        dialog_state={},
        followup_hint={},
        tool_traces=[
            {
                "tool_name": "get_task_detail",
                "arguments": {"task_id": "task-1"},
                "ok": True,
                "result": {
                    "task_type": TaskType.ASSET_SCAN,
                    "status": TaskExecutionStatus.SUCCESS,
                    "created_at": base,
                    "timing": {"last_seen_at": base},
                },
            }
        ],
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    serialized_messages = [message.text_content() for message in request.messages if message.role == "user"]

    assert any(base.isoformat() in message for message in serialized_messages)
    assert any('"task_type": "asset_scan"' in message for message in serialized_messages)
    assert any('"status": "success"' in message for message in serialized_messages)


def test_parse_model_decision_allows_null_retryable_and_normalizes_it() -> None:
    decision = haor_agent_service._parse_model_decision(
        """
        {
          "reply_markdown": "我先展开当前详情。",
          "conversation_state": "answer",
          "ui_actions": [
            {
              "action_id": "ui-1",
              "action_type": "click",
              "target_node_id": "node-1",
              "retryable": null
            }
          ]
        }
        """
    )

    assert decision.ui_actions[0].retryable is None
    assert haor_agent_service._normalize_model_ui_actions(decision.ui_actions)[0]["retryable"] is True


def test_parse_model_decision_normalizes_dialog_state_intent_kind_alias() -> None:
    decision = haor_agent_service._parse_model_decision(
        """
        {
          "reply_markdown": "我先确认是否执行扫描。",
          "conversation_state": "clarifying",
          "clarifying_question": "是否立即扫描这个网段？",
          "dialog_state_update": {
            "status": "awaiting_user_input",
            "intent_kind": "operate_low_risk",
            "question_kind": "confirm",
            "intent_summary": "扫描当前网段",
            "last_agent_question": "是否立即扫描这个网段？"
          }
        }
        """
    )

    assert decision.dialog_state_update is not None
    assert decision.dialog_state_update.intent_kind == "prepare_plan"


def test_parse_model_decision_normalizes_schema_drift_aliases() -> None:
    decision = haor_agent_service._parse_model_decision(
        """
        {
          "reply_markdown": "我来继续推进。",
          "conversation_state": "completed",
          "read_tool_calls": null,
          "needs_confirmation": "false",
          "followup_resolution": "继续承接上一轮"
        }
        """
    )

    assert decision.conversation_state == "answer"
    assert decision.read_tool_calls == []
    assert decision.needs_confirmation is False
    assert decision.followup_resolution is not None
    assert decision.followup_resolution.status == "unknown"
    assert decision.followup_resolution.summary == "继续承接上一轮"


def test_normalize_dialog_state_accepts_objective_kind_alias() -> None:
    normalized = haor_agent_service._normalize_dialog_state(
        {
            "status": "awaiting_user_input",
            "intent_kind": "inspect",
            "question_kind": "followup",
            "intent_summary": "查看当前任务详情",
            "last_agent_question": "是否继续查看任务详情？",
        }
    )

    assert normalized["intent_kind"] == "read_followup"


def test_append_or_stream_assistant_message_uses_draft_reply_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    events: list[dict] = []
    session = SimpleNamespace(id="session-1", updated_at=None)

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "custom_proxy")

    def _unexpected_provider():
        raise AssertionError("reply rewrite provider should stay disabled by default")

    monkeypatch.setattr(haor_agent_service, "_build_runtime_provider", _unexpected_provider)

    message = haor_agent_service._append_or_stream_assistant_message(
        _FakeUnitDB(),
        session=session,
        message_type="text",
        content="原始草稿回复",
        payload_json={},
        user_content="你好",
        tool_traces=[],
        working_context={},
        stream_emitter=events.append,
        turn_id="turn-text",
    )

    delta_text = "".join(str(item.get("delta") or "") for item in events if item.get("type") == "assistant_message_delta")
    done_event = next(item for item in events if item.get("type") == "assistant_message_done")

    assert delta_text == "原始草稿回复"
    assert done_event["message"]["content"] == "原始草稿回复"
    assert message.content == "原始草稿回复"


def test_append_or_stream_assistant_message_scrubs_reply_stream_output_when_rewrite_enabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class _FakeProvider:
        def stream_generate(self, _request):
            yield '<think>用户只是打了个招呼"你好"，confirmed_reply_draft 已经准备好了回复。'
            yield "working_context 和 tool_trace_summary 都是空的，说明没有需要调用工具。"
            yield "我需要把 confirmed_reply_draft 直接整理输出给用户。</think>\n\n你好！有什么我可以帮助你的吗？"

    events: list[dict] = []
    session = SimpleNamespace(id="session-1", updated_at=None)

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "custom_proxy")
    monkeypatch.setattr(haor_agent_service, "_haor_reply_rewrite_enabled", lambda: True)
    monkeypatch.setattr(
        haor_agent_service,
        "_build_runtime_provider",
        lambda: SimpleNamespace(provider=_FakeProvider()),
    )

    message = haor_agent_service._append_or_stream_assistant_message(
        _FakeUnitDB(),
        session=session,
        message_type="text",
        content="原始草稿回复",
        payload_json={},
        user_content="你好",
        tool_traces=[],
        working_context={},
        stream_emitter=events.append,
        turn_id="turn-text",
    )

    delta_text = "".join(str(item.get("delta") or "") for item in events if item.get("type") == "assistant_message_delta")
    done_event = next(item for item in events if item.get("type") == "assistant_message_done")

    assert delta_text == "你好！有什么我可以帮助你的吗？"
    assert "<think>" not in delta_text
    assert "confirmed_reply_draft" not in delta_text
    assert done_event["message"]["content"] == "你好！有什么我可以帮助你的吗？"
    assert message.content == "你好！有什么我可以帮助你的吗？"


def test_apply_agent_decision_updates_pending_plan_reply_to_streamed_content(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class _FakeProvider:
        def stream_generate(self, _request):
            yield "<think>confirmed_reply_draft 已经准备好了回复。</think>\n\n精简"
            yield "计划摘要"

    events: list[dict] = []
    session = SimpleNamespace(
        id="session-1",
        status="active",
        pending_plan_json={},
        dialog_state_json={},
        browser_runtime_json={},
        working_context_json={},
        updated_at=None,
    )
    decision = haor_agent_service._AgentModelDecision(
        reply_markdown="原始计划摘要",
        conversation_state="answer",
        proposed_write_actions=[
            haor_agent_service._ProposedWriteAction(
                action_type="verify_asset_risks",
                title="验证风险",
                reason="确认当前风险状态",
                params={"asset_id": "asset-1"},
            )
        ],
        needs_confirmation=True,
    )

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "custom_proxy")
    monkeypatch.setattr(haor_agent_service, "_haor_reply_rewrite_enabled", lambda: True)
    monkeypatch.setattr(
        haor_agent_service,
        "_build_runtime_provider",
        lambda: SimpleNamespace(provider=_FakeProvider()),
    )

    haor_agent_service._apply_agent_decision(
        _FakeUnitDB(),
        session=session,
        user=SimpleNamespace(id="user-1", role="admin"),
        decision=decision,
        tool_traces=[],
        page_context={"pathname": "/assets/asset-1", "query": {}, "asset_id": "asset-1"},
        browser_context={"pathname": "/assets/asset-1", "query": {}, "asset_id": "asset-1"},
        current_browser_runtime={},
        working_context={
            "asset_id": "asset-1",
            "primary_target": {"asset_id": "asset-1"},
            "recent_targets": [{"asset_id": "asset-1"}],
        },
        dialog_state={},
        followup_hint={},
        user_content="生成修复计划",
        existing_pending_plan={},
        has_pending_plan=False,
        platform_url="http://testserver",
        stream_emitter=events.append,
        turn_id="turn-plan",
    )

    assert session.status == "waiting_approval"
    assert session.pending_plan_json["reply_markdown"] == "精简计划摘要"
    assert any(item.get("type") == "assistant_message_delta" and "confirmed_reply_draft" not in str(item.get("delta")) for item in events)
    assert any(
        item.get("type") == "assistant_message_done" and item.get("message", {}).get("content") == "精简计划摘要"
        for item in events
    )
    assert any(
        item.get("type") == "plan_pending" and item.get("pending_plan_json", {}).get("reply_markdown") == "精简计划摘要"
        for item in events
    )


def test_apply_agent_decision_updates_dialog_state_question_to_streamed_content(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class _FakeProvider:
        def stream_generate(self, _request):
            yield "<think>pending_dialog_state 和 followup_hint 已存在。</think>\n\n请先确认"
            yield "要分析的资产。"

    events: list[dict] = []
    session = SimpleNamespace(
        id="session-1",
        status="active",
        pending_plan_json={},
        dialog_state_json={},
        browser_runtime_json={},
        working_context_json={},
        updated_at=None,
    )
    decision = haor_agent_service._AgentModelDecision(
        reply_markdown="请先确认资产。",
        conversation_state="clarifying",
        clarifying_question="请先确认资产。",
        dialog_state_update=haor_agent_service._DialogState(
            status="awaiting_user_input",
            intent_kind="fill_slot",
            question_kind="disambiguate",
            intent_summary="确认要分析的资产",
            last_agent_question="请先确认资产。",
            targets_snapshot={"working_context": {"asset_id": "asset-1"}},
        ),
    )

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "custom_proxy")
    monkeypatch.setattr(haor_agent_service, "_haor_reply_rewrite_enabled", lambda: True)
    monkeypatch.setattr(
        haor_agent_service,
        "_build_runtime_provider",
        lambda: SimpleNamespace(provider=_FakeProvider()),
    )

    haor_agent_service._apply_agent_decision(
        _FakeUnitDB(),
        session=session,
        user=SimpleNamespace(id="user-1", role="admin"),
        decision=decision,
        tool_traces=[],
        page_context={"pathname": "/assets", "query": {}},
        browser_context={"pathname": "/assets", "query": {}},
        current_browser_runtime={},
        working_context={"asset_id": "asset-1", "recent_targets": [{"asset_id": "asset-1"}]},
        dialog_state={},
        followup_hint={},
        user_content="继续",
        existing_pending_plan={},
        has_pending_plan=False,
        platform_url="http://testserver",
        stream_emitter=events.append,
        turn_id="turn-clarifying",
    )

    assert session.dialog_state_json["last_agent_question"] == "请先确认要分析的资产。"
    assert any(
        item.get("type") == "assistant_message_done" and item.get("message", {}).get("content") == "请先确认要分析的资产。"
        for item in events
    )


def test_build_runtime_provider_prefers_runtime_env_values_over_cached_settings(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    runtime_values = {
        "LLM_PROVIDER": "custom_proxy",
        "LLM_MODEL": "gpt-5.4",
        "LLM_BASE_URL": "relay.runtime.example.com/models",
        "LLM_WIRE_API": "auto",
        "LLM_TIMEOUT_SECONDS": "42",
        "LLM_API_KEY": "sk-runtime-new",
    }

    monkeypatch.setattr(
        haor_agent_service,
        "read_runtime_env_value",
        lambda key, fallback="": str(runtime_values.get(key, fallback)),
    )
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(haor_agent_service.settings, "LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setattr(haor_agent_service.settings, "LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setattr(haor_agent_service.settings, "LLM_WIRE_API", "responses")
    monkeypatch.setattr(haor_agent_service.settings, "LLM_TIMEOUT_SECONDS", 20)
    monkeypatch.setattr(haor_agent_service.settings, "LLM_API_KEY", "sk-cached-old")

    result = haor_agent_service._build_runtime_provider()

    assert result.provider_name == "custom_proxy"
    assert result.resolved_base_url == "https://relay.runtime.example.com/v1"
    assert result.provider.model == "gpt-5.4"
    assert result.provider.timeout_seconds == 42
    assert result.provider.api_key == "sk-runtime-new"
    assert result.provider.wire_api == "auto"


def test_build_runtime_snapshot_keeps_input_enabled_while_watching_task() -> None:
    goal = AgentGoal(
        id="goal-1",
        user_id="user-1",
        agent_id="haor",
        status="active",
        title="验证资产风险",
        goal_kind="verify_asset_risks",
    )
    session = SimpleNamespace(
        status="running",
        browser_runtime_json={"phase": "running", "objective_kind": "inspect"},
        agent_state_json={"watch": {"watching": True, "primary_task_id": "task-1"}},
        pending_plan_json={},
        last_task_id="task-1",
        current_goal=goal,
    )

    snapshot = haor_agent_service._build_runtime_snapshot(session)

    assert snapshot.phase == "watching_task"
    assert snapshot.input_state == "enabled"
    assert snapshot.input_block_reason == "none"
    assert snapshot.watch_task_id == "task-1"
    assert snapshot.can_interrupt is True
    assert snapshot.active_skill_title == "验证资产风险"


def test_serialize_agent_session_summary_uses_runtime_watch_task_id_for_attention() -> None:
    session = SimpleNamespace(
        status="running",
        browser_runtime_json={"phase": "running"},
        agent_state_json={"watch": {"watching": True, "primary_task_id": "task-2"}},
        pending_plan_json={},
        last_task_id=None,
        current_goal=None,
        updated_at=datetime.now(UTC),
    )

    summary = haor_agent_service.serialize_agent_session_summary(session)

    assert summary.attention_kind == "running_task"
    assert summary.runtime_phase == "watching_task"
    assert summary.input_state == "enabled"
    assert summary.last_task_id == "task-2"


def test_recover_agent_session_repairs_stale_wait_and_unlocks_input(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    session = SimpleNamespace(
        id="session-1",
        agent_id="haor",
        status="active",
        route_context_json={},
        working_context_json={"asset_id": "asset-1"},
        dialog_state_json={},
        pending_plan_json={},
        browser_runtime_json={"phase": "awaiting_agent_reply", "last_user_intent": "继续"},
        agent_state_json={},
        current_goal=None,
        current_goal_id=None,
        last_task_id=None,
        messages=[],
        created_at=now,
        updated_at=now,
    )
    db = _FakeRecoverDB()

    monkeypatch.setattr(haor_agent_service, "_load_recent_session", lambda _db, user_id: session)

    result = haor_agent_service.recover_agent_session(db, user=SimpleNamespace(id="user-1"))

    assert db.committed is True
    assert db.refreshed == [session]
    assert session.browser_runtime_json["phase"] == "idle"
    assert session.browser_runtime_json["current_message_request_id"] is None
    assert result.status == "active"
    assert result.runtime_snapshot.phase == "idle"
    assert result.runtime_snapshot.input_state == "enabled"


def test_recover_agent_session_unlocks_when_terminal_followup_already_exists(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    session = SimpleNamespace(
        id="session-1",
        agent_id="haor",
        status="active",
        route_context_json={"pathname": "/tasks/task-1", "query": {}, "task_id": "task-1"},
        working_context_json={"task_id": "task-1"},
        dialog_state_json={},
        pending_plan_json={},
        browser_runtime_json={
            "phase": "awaiting_ui_feedback",
            "pending_ui_actions": [{"action_id": "ui-1", "action_type": "navigate", "href": "/tasks/task-1"}],
            "last_browser_context": {"pathname": "/tasks/task-1", "query": {}, "task_id": "task-1"},
            "last_user_intent": "继续当前站内动作",
            "current_objective": "查看扫描结果",
            "objective_kind": "scan_and_analyze_cidr",
        },
        agent_state_json={"watch": {"watching": True, "primary_task_id": "task-1"}},
        current_goal=None,
        current_goal_id=None,
        last_task_id="task-1",
        messages=[
            SimpleNamespace(
                id="msg-1",
                role="assistant",
                message_type="task_update",
                content="任务 task-1 已完成",
                payload_json={
                    "task_id": "task-1",
                    "terminal_status": "success",
                    "auto_followup": True,
                    "action": {"action_type": "create_discovery_job"},
                },
                created_at=now,
            )
        ],
        created_at=now,
        updated_at=now,
    )
    db = _FakeRecoverDB()

    monkeypatch.setattr(haor_agent_service, "_load_recent_session", lambda _db, user_id: session)

    result = haor_agent_service.recover_agent_session(db, user=SimpleNamespace(id="user-1"))

    assert db.committed is True
    assert session.browser_runtime_json["phase"] == "idle"
    assert result.runtime_snapshot.input_state == "enabled"
    assert result.runtime_snapshot.input_block_reason == "none"


def test_append_agent_task_message_clears_stale_ui_phase_and_unlocks_input() -> None:
    now = datetime.now(UTC)
    session = SimpleNamespace(
        id="session-1",
        status="active",
        route_context_json={"pathname": "/tasks/task-1", "query": {}, "task_id": "task-1"},
        working_context_json={"task_id": "task-1"},
        dialog_state_json={},
        pending_plan_json={},
        browser_runtime_json={
            "phase": "resolving_ui_feedback",
            "pending_ui_actions": [],
            "completed_ui_actions": [],
            "last_ui_results": [],
            "last_browser_context": {"pathname": "/tasks/task-1", "query": {}, "task_id": "task-1"},
            "last_user_intent": "继续当前站内动作",
            "current_objective": "查看扫描结果",
            "objective_kind": "scan_and_analyze_cidr",
            "auto_executed_actions": [{"action_type": "create_discovery_job"}],
            "last_step_request_id": "step-1",
        },
        agent_state_json={"watch": {"watching": True, "primary_task_id": "task-1"}},
        current_goal=None,
        current_goal_id=None,
        last_task_id="task-1",
        messages=[],
        created_at=now,
        updated_at=now,
    )
    db = _FakeMessageDB(session)

    haor_agent_service.append_agent_task_message(
        db,
        session_id="session-1",
        content="任务 task-1 已完成",
        payload_json={"task_id": "task-1", "child_task": {"task_id": "task-1", "status": "success"}},
        message_type="task_update",
    )

    snapshot = haor_agent_service._build_runtime_snapshot(session)

    assert session.browser_runtime_json["phase"] == "idle"
    assert session.browser_runtime_json["pending_ui_actions"] == []
    assert snapshot.phase == "idle"
    assert snapshot.input_state == "enabled"
    assert snapshot.input_block_reason == "none"


def test_normalize_assistant_reply_content_deduplicates_repeated_sentences_and_blocks() -> None:
    content = (
        "未查询到 192.168.10.0/24 的现有资产。是否立即发起扫描？未指定标签时将使用默认标签。"
        "未查询到 192.168.10.0/24 的现有资产。是否立即发起扫描？未指定标签时将使用默认标签。\n\n"
        "已开始扫描 192.168.10.0/24，当前使用默认标签。\n\n"
        "已开始扫描 192.168.10.0/24，当前使用默认标签。"
    )

    normalized = haor_agent_service._normalize_assistant_reply_content(content)

    assert normalized.count("未查询到 192.168.10.0/24 的现有资产。") == 1
    assert normalized.count("已开始扫描 192.168.10.0/24，当前使用默认标签。") == 1


def test_normalize_assistant_reply_content_removes_think_and_internal_scaffold_blocks() -> None:
    content = (
        '<think>用户只是打了个招呼"你好"，confirmed_reply_draft 已经准备好了回复。'
        "working_context 和 tool_trace_summary 都是空的，说明没有需要调用工具。"
        "我需要把 confirmed_reply_draft 直接整理输出给用户。</think>\n\n"
        "confirmed_reply_draft 已经准备好了回复。\n\n"
        "你好！有什么我可以帮助你的吗？\n\n"
        "tool_trace_summary: []"
    )

    normalized = haor_agent_service._normalize_assistant_reply_content(content)

    assert normalized == "你好！有什么我可以帮助你的吗？"


def test_normalize_assistant_reply_content_preserves_list_items() -> None:
    content = "- [create_discovery_job] 已创建扫描任务 task-1\n- [verify_asset_risks] 已触发资产 asset-1 的风险验证"

    normalized = haor_agent_service._normalize_assistant_reply_content(content)

    assert normalized == content


def test_resolve_working_context_keeps_soft_focus_when_page_changes_without_reference() -> None:
    session = SimpleNamespace(
        working_context_json={
            "asset_id": "asset-1",
            "source": "page_reference",
            "summary": "资产 asset-1",
            "primary_target": {"asset_id": "asset-1", "source": "page_reference", "summary": "资产 asset-1"},
            "recent_targets": [{"asset_id": "asset-1", "source": "page_reference", "summary": "资产 asset-1"}],
        }
    )

    working_context = haor_agent_service._resolve_working_context_for_message(
        db=_FakeLookupDB(),
        session=session,
        content="继续分析",
        page_context={"pathname": "/assets/asset-2", "query": {}, "asset_id": "asset-2", "finding_id": None, "task_id": None},
    )

    assert working_context["asset_id"] == "asset-1"
    assert working_context["primary_target"]["asset_id"] == "asset-1"


def test_resolve_working_context_switches_focus_when_message_mentions_new_target() -> None:
    session = SimpleNamespace(
        working_context_json={
            "asset_id": "asset-1",
            "source": "page_reference",
            "summary": "资产 asset-1",
            "primary_target": {"asset_id": "asset-1", "source": "page_reference", "summary": "资产 asset-1"},
            "recent_targets": [{"asset_id": "asset-1", "source": "page_reference", "summary": "资产 asset-1"}],
        }
    )

    working_context = haor_agent_service._resolve_working_context_for_message(
        db=_FakeLookupDB(),
        session=session,
        content="帮我处理资产 asset-2",
        page_context={"pathname": "/assets/asset-2", "query": {}, "asset_id": "asset-2", "finding_id": None, "task_id": None},
    )

    assert working_context["asset_id"] == "asset-2"
    assert working_context["primary_target"]["asset_id"] == "asset-2"
    assert [item["asset_id"] for item in working_context["recent_targets"]][:2] == ["asset-2", "asset-1"]


def test_resolve_working_context_prefers_current_page_reference_over_previous_focus() -> None:
    session = SimpleNamespace(
        working_context_json={
            "asset_id": "asset-1",
            "source": "page_reference",
            "summary": "资产 asset-1",
            "primary_target": {"asset_id": "asset-1", "source": "page_reference", "summary": "资产 asset-1"},
            "recent_targets": [{"asset_id": "asset-1", "source": "page_reference", "summary": "资产 asset-1"}],
        }
    )

    working_context = haor_agent_service._resolve_working_context_for_message(
        db=_FakeLookupDB(),
        session=session,
        content="继续看这个资产",
        page_context={"pathname": "/assets/asset-2", "query": {}, "asset_id": "asset-2", "finding_id": None, "task_id": None},
    )

    assert working_context["asset_id"] == "asset-2"
    assert working_context["primary_target"]["asset_id"] == "asset-2"


def test_resolve_working_context_restores_dialog_snapshot_for_affirm_followup() -> None:
    session = SimpleNamespace(working_context_json={})

    working_context = haor_agent_service._resolve_working_context_for_message(
        db=_FakeLookupDB(),
        session=session,
        content="确认",
        page_context={"pathname": "/", "query": {}, "asset_id": None, "finding_id": None, "task_id": None},
        dialog_state={
            "status": "awaiting_user_input",
            "intent_kind": "read_followup",
            "question_kind": "confirm",
            "intent_summary": "查看资产风险",
            "last_agent_question": "是否继续查看资产风险？",
            "targets_snapshot": {"working_context": {"asset_id": "asset-1"}},
        },
        followup_hint={"reply_kind": "affirm", "raw_user_reply": "确认"},
    )

    assert working_context["asset_id"] == "asset-1"
    assert session.working_context_json["asset_id"] == "asset-1"


def test_resolve_working_context_uses_browser_semantic_primary_entity_for_current_reference() -> None:
    session = SimpleNamespace(working_context_json={})

    working_context = haor_agent_service._resolve_working_context_for_message(
        db=_FakeLookupDB(),
        session=session,
        content="继续看这个任务",
        page_context={"pathname": "/tasks", "query": {}, "asset_id": None, "finding_id": None, "task_id": None},
        browser_context={
            "pathname": "/tasks",
            "query": {},
            "semantic_page_context": {
                "page_kind": "task_detail",
                "primary_entity": {"kind": "task", "id": "task-1", "label": "任务 task-1"},
            },
        },
    )

    assert working_context["task_id"] == "task-1"
    assert working_context["primary_target"]["task_id"] == "task-1"


def test_resolve_working_context_ignores_dashboard_platform_primary_entity() -> None:
    session = SimpleNamespace(working_context_json={})

    working_context = haor_agent_service._resolve_working_context_for_message(
        db=_FakeLookupDB(),
        session=session,
        content="帮我修复这个",
        page_context={"pathname": "/", "query": {}, "asset_id": None, "finding_id": None, "task_id": None},
        browser_context={
            "pathname": "/",
            "query": {},
            "semantic_page_context": {
                "page_kind": "dashboard_overview",
                "primary_entity": {"kind": "platform", "id": "dashboard", "label": "桌面态势总览"},
            },
        },
    )

    assert working_context == {}


def test_resolve_asset_for_read_tool_accepts_ip_reference(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    asset = SimpleNamespace(id="asset-1", ip="192.168.130.138", hostname="host-1")
    observed: dict[str, object] = {}

    monkeypatch.setattr(haor_agent_service, "get_asset", lambda db, asset_id: None)

    def _fake_list_assets(db, page, page_size, ip=None, keyword=None, asset_status=None, tag_id=None):  # type: ignore[no-untyped-def]
        observed["ip"] = ip
        observed["keyword"] = keyword
        if ip == "192.168.130.138":
            return [asset], 1
        return [], 0

    monkeypatch.setattr(haor_agent_service, "list_assets", _fake_list_assets)

    resolved = haor_agent_service._resolve_asset_for_read_tool(SimpleNamespace(), "192.168.130.138")

    assert resolved is asset
    assert observed["ip"] == "192.168.130.138"


def test_execute_read_tool_list_asset_risks_accepts_host_cidr_reference(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    asset = SimpleNamespace(id="asset-1", ip="192.168.130.138", hostname="host-1")
    observed: dict[str, object] = {}

    monkeypatch.setattr(haor_agent_service, "get_asset", lambda db, asset_id: None)

    def _fake_list_assets(db, page, page_size, ip=None, keyword=None, asset_status=None, tag_id=None):  # type: ignore[no-untyped-def]
        observed["ip"] = ip
        observed["keyword"] = keyword
        if ip == "192.168.130.138":
            return [asset], 1
        return [], 0

    monkeypatch.setattr(haor_agent_service, "list_assets", _fake_list_assets)
    monkeypatch.setattr(
        haor_agent_service,
        "list_findings_by_asset",
        lambda db, asset_id: [SimpleNamespace(id="finding-1", status=SimpleNamespace(value="open"), severity=SimpleNamespace(value="high"), title="匿名 FTP", rule_id="ftp.anonymous.enabled", asset_id=asset_id, asset=None, rule=None, created_at=None, updated_at=None)],
    )
    monkeypatch.setattr(
        haor_agent_service,
        "_serialize_finding_summary",
        lambda item: {"finding_id": item.id, "asset_id": item.asset_id, "severity": item.severity.value},
    )

    result = haor_agent_service._execute_read_tool(
        SimpleNamespace(),
        tool_name="list_asset_risks",
        arguments={"asset_id": "192.168.130.138/32", "limit": 10},
    )

    assert result["asset_id"] == "asset-1"
    assert result["items"][0]["asset_id"] == "asset-1"
    assert observed["ip"] == "192.168.130.138"


def test_agent_message_request_accepts_legacy_route_context_alias() -> None:
    payload = AgentMessageCreateRequest.model_validate(
        {
            "content": "分析当前页面",
            "route_context": {"pathname": "/assets/asset-1", "query": {}, "asset_id": "asset-1"},
        }
    )

    assert payload.page_context.asset_id == "asset-1"


def test_preserve_or_reset_pending_plan_keeps_waiting_approval_when_requested() -> None:
    session = SimpleNamespace(status="active", pending_plan_json={})
    existing_pending_plan = {
        "reply_markdown": "待确认计划",
        "proposed_write_actions": [{"action_type": "verify_asset_risks"}],
    }

    haor_agent_service._preserve_or_reset_pending_plan(
        session,
        existing_pending_plan=existing_pending_plan,
        preserve_existing=True,
    )

    assert session.status == "waiting_approval"
    assert session.pending_plan_json == existing_pending_plan


def test_build_followup_hint_detects_affirm_for_pending_dialog() -> None:
    dialog_state = {
        "status": "awaiting_user_input",
        "intent_kind": "read_followup",
        "question_kind": "confirm",
        "intent_summary": "查看任务详情",
        "last_agent_question": "是否继续查看任务详情以便分析？",
        "expected_slots": [],
        "candidate_read_tools": [{"tool_name": "get_task_detail", "arguments": {"task_id": "task-1"}}],
        "candidate_write_context": {},
        "targets_snapshot": {"working_context": {"task_id": "task-1"}},
    }

    hint = haor_agent_service._build_followup_hint("继续", dialog_state)

    assert hint["reply_kind"] == "affirm"
    assert hint["raw_user_reply"] == "继续"


def test_build_followup_hint_extracts_short_value_for_expected_slot() -> None:
    dialog_state = {
        "status": "awaiting_user_input",
        "intent_kind": "fill_slot",
        "question_kind": "slot_fill",
        "intent_summary": "查看任务详情",
        "last_agent_question": "请告诉我要查看的任务 ID。",
        "expected_slots": ["task_id"],
        "candidate_read_tools": [],
        "candidate_write_context": {},
        "targets_snapshot": {},
    }

    hint = haor_agent_service._build_followup_hint("task-123", dialog_state)

    assert hint["reply_kind"] == "short_value"
    assert hint["extracted_values"]["task_id"] == "task-123"


def test_build_internal_scan_clarifying_decision_uses_fixed_question_when_cidr_assets_missing() -> None:
    decision = haor_agent_service._build_internal_scan_clarifying_decision(
        user_content="帮我分析 192.168.10.0/24 资产的漏洞",
        page_context={"pathname": "/", "query": {}},
        working_context={},
        dialog_state={},
        tool_traces=[
            {
                "tool_name": "list_assets",
                "arguments": {"keyword": "192.168.10.0/24"},
                "ok": True,
                "result": {"items": [], "total": 0},
            }
        ],
    )

    assert decision is not None
    assert decision.conversation_state == "clarifying"
    assert decision.clarifying_question == "未查询到 192.168.10.0/24 的现有资产。是否立即发起扫描？未指定标签时将使用默认标签。"
    assert decision.dialog_state_update is not None
    assert decision.dialog_state_update.candidate_write_context["action_type"] == "create_discovery_job"
    assert decision.dialog_state_update.candidate_write_context["params"]["cidr"] == "192.168.10.0/24"
    assert decision.dialog_state_update.candidate_write_context["allow_affirm_execute"] is True


def test_build_internal_followup_decision_executes_discovery_scan_on_affirm_with_default_label() -> None:
    decision = haor_agent_service._build_internal_followup_decision(
        user=SimpleNamespace(role="admin"),
        user_content="是的",
        dialog_state={
            "status": "awaiting_user_input",
            "intent_kind": "prepare_plan",
            "question_kind": "confirm",
            "intent_summary": "先扫描再分析漏洞",
            "last_agent_question": "未查询到 192.168.10.0/24 的现有资产。是否立即发起扫描？未指定标签时将使用默认标签。",
            "candidate_write_context": {
                "action_type": "create_discovery_job",
                "params": {"cidr": "192.168.10.0/24"},
                "optional_defaults": {"label": None},
                "allow_affirm_execute": True,
            },
        },
        followup_hint={"reply_kind": "affirm", "raw_user_reply": "是的"},
    )

    assert decision is not None
    assert decision.auto_execute_actions[0].action_type == "create_discovery_job"
    assert decision.auto_execute_actions[0].params["cidr"] == "192.168.10.0/24"
    assert "label" not in decision.auto_execute_actions[0].params


def test_extract_cidr_target_normalizes_host_bits() -> None:
    assert haor_agent_service._extract_cidr_target("请扫描 192.168.10.1/24") == "192.168.10.0/24"


def test_build_internal_followup_decision_uses_explicit_label_override() -> None:
    decision = haor_agent_service._build_internal_followup_decision(
        user=SimpleNamespace(role="admin"),
        user_content="标签写 office-net",
        dialog_state={
            "status": "awaiting_user_input",
            "intent_kind": "prepare_plan",
            "question_kind": "confirm",
            "intent_summary": "先扫描再分析漏洞",
            "last_agent_question": "未查询到 192.168.10.0/24 的现有资产。是否立即发起扫描？未指定标签时将使用默认标签。",
            "candidate_write_context": {
                "action_type": "create_discovery_job",
                "params": {"cidr": "192.168.10.0/24"},
                "optional_defaults": {"label": None},
                "allow_affirm_execute": True,
            },
        },
        followup_hint={"reply_kind": "unknown", "raw_user_reply": "标签写 office-net"},
    )

    assert decision is not None
    assert decision.auto_execute_actions[0].params["label"] == "office-net"


def test_build_auto_execute_reply_markdown_avoids_repeating_action_update_summary() -> None:
    reply = haor_agent_service._build_auto_execute_reply_markdown(
        [
            {
                "action_type": "create_discovery_job",
                "summary": "已创建扫描任务 task-1",
                "params": {"cidr": "192.168.10.0/24"},
                "payload": {"task_id": "task-1", "reused": False},
            }
        ],
        user_content="帮我分析 192.168.10.0/24 资产的漏洞",
        fallback="已自动执行 1 个低风险动作。\n- [create_discovery_job] 已创建扫描任务 task-1",
    )

    assert "已自动执行 1 个低风险动作" not in reply
    assert "task-1" not in reply
    assert "已开始扫描 192.168.10.0/24" in reply
    assert "继续帮你分析该网段资产的漏洞" in reply


def test_promote_resolved_targets_from_tool_traces_uses_asset_risk_and_task_results() -> None:
    asset_context = haor_agent_service._promote_resolved_targets_from_tool_traces(
        [
            {
                "tool_name": "list_asset_risks",
                "arguments": {"asset_id": "asset-1"},
                "ok": True,
                "result": {"asset_id": "asset-1", "items": [], "total": 0},
            }
        ],
        {},
    )
    assert asset_context["asset_id"] == "asset-1"

    finding_context = haor_agent_service._promote_resolved_targets_from_tool_traces(
        [
            {
                "tool_name": "get_risk_detail",
                "arguments": {"finding_id": "finding-1"},
                "ok": True,
                "result": {"finding_id": "finding-1", "asset_id": "asset-1"},
            }
        ],
        {},
    )
    assert finding_context["finding_id"] == "finding-1"
    assert finding_context["asset_id"] == "asset-1"

    task_context = haor_agent_service._promote_resolved_targets_from_tool_traces(
        [
            {
                "tool_name": "get_task_detail",
                "arguments": {"task_id": "task-1"},
                "ok": True,
                "result": {"id": "task-1", "scope_type": "asset", "scope_id": "asset-9"},
            }
        ],
        {},
    )
    assert task_context["task_id"] == "task-1"
    assert task_context["asset_id"] == "asset-9"


def test_promote_resolved_targets_from_tool_traces_does_not_guess_from_multi_result_lists() -> None:
    working_context = haor_agent_service._promote_resolved_targets_from_tool_traces(
        [
            {
                "tool_name": "list_assets",
                "arguments": {},
                "ok": True,
                "result": {
                    "items": [
                        {"asset_id": "asset-1"},
                        {"asset_id": "asset-2"},
                    ],
                    "total": 2,
                },
            }
        ],
        {},
    )

    assert working_context == {}


def test_run_agent_loop_persists_promoted_focus_before_model_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(
        messages=[SimpleNamespace(role="user", message_type="text", content="查看风险")],
        working_context_json={},
    )
    user = SimpleNamespace(role="admin")
    call_count = {"value": 0}

    def _fake_run_model_once(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        if call_count["value"] == 1:
            return haor_agent_service._AgentModelDecision(
                reply_markdown="继续读取",
                conversation_state="answer",
                read_tool_calls=[
                    haor_agent_service._ReadToolCall(
                        tool_name="list_asset_risks",
                        arguments={"asset_id": "asset-1"},
                    )
                ],
            )
        raise httpx.RequestError("boom")

    monkeypatch.setattr(haor_agent_service, "_run_model_once", _fake_run_model_once)
    monkeypatch.setattr(
        haor_agent_service,
        "_execute_read_tool",
        lambda db, *, tool_name, arguments: {"asset_id": arguments["asset_id"], "items": [], "total": 0},
    )

    try:
        haor_agent_service._run_agent_loop(
            db=SimpleNamespace(),
            session=session,
            user=user,
            page_context={"pathname": "/", "query": {}},
            browser_context={"pathname": "/", "query": {}},
            browser_runtime={},
            working_context={},
            dialog_state={},
            followup_hint={},
            allow_write_plans=True,
            allow_auto_execute_actions=True,
        )
    except httpx.RequestError:
        pass
    else:
        raise AssertionError("expected httpx.RequestError")

    assert session.working_context_json["asset_id"] == "asset-1"


def test_run_agent_loop_prefers_latest_user_message_over_stale_last_user_intent(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(role="assistant", message_type="action_update", content="请继续"),
            SimpleNamespace(role="user", message_type="text", content="继续验证资产 asset-1 的风险"),
        ],
        working_context_json={"asset_id": "asset-1"},
    )
    user = SimpleNamespace(role="admin")

    def _unexpected_model_call(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("playbook should resolve the latest user intent before model fallback")

    monkeypatch.setattr(haor_agent_service, "_run_model_once", _unexpected_model_call)

    decision, tool_traces = haor_agent_service._run_agent_loop(
        db=SimpleNamespace(),
        session=session,
        user=user,
        page_context={"pathname": "/", "query": {}, "asset_id": "asset-1"},
        browser_context={"pathname": "/", "query": {}, "asset_id": "asset-1"},
        browser_runtime={"last_user_intent": "自动修复"},
        working_context={"asset_id": "asset-1"},
        dialog_state={},
        followup_hint={},
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert tool_traces == []
    assert decision.auto_execute_actions[0].action_type == "verify_asset_risks"
    assert decision.auto_execute_actions[0].params["asset_id"] == "asset-1"
    assert decision.proposed_write_actions == []


def test_build_action_first_fallback_decision_prefers_semantic_ui_action() -> None:
    user = SimpleNamespace(role="admin")

    decision = haor_agent_service._build_action_first_fallback_decision(
        content="打开事件日志并分析失败原因",
        user=user,
        page_context={"pathname": "/tasks/task-1", "query": {}, "task_id": "task-1"},
        browser_context={
            "pathname": "/tasks/task-1",
            "query": {},
            "task_id": "task-1",
            "semantic_page_context": {
                "page_kind": "task_detail",
                "primary_entity": {"kind": "task", "id": "task-1", "label": "任务 task-1"},
                "visible_sections": [{"section_id": "task_detail:section:events", "label": "事件日志"}],
                "semantic_actions": [
                    {
                        "semantic_action_id": "task_detail:scroll:task_detail:section:events",
                        "label": "定位到 事件日志",
                        "action_type": "scroll_into_view",
                        "node_id": "haor-node-1",
                        "section_id": "task_detail:section:events",
                        "keywords": ["事件", "日志", "定位"],
                    }
                ],
            },
        },
        working_context={
            "task_id": "task-1",
            "primary_target": {"task_id": "task-1"},
            "recent_targets": [{"task_id": "task-1"}],
        },
        dialog_state={},
        followup_hint={},
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert decision is not None
    assert decision.stop_reason == "action_first_ui"
    assert decision.ui_actions[0].semantic_action_id == "task_detail:scroll:task_detail:section:events"


def test_build_action_first_fallback_decision_auto_executes_low_risk_scan() -> None:
    user = SimpleNamespace(role="admin")

    decision = haor_agent_service._build_action_first_fallback_decision(
        content="扫描 192.168.10.0/24 网段",
        user=user,
        page_context={"pathname": "/", "query": {}},
        browser_context={"pathname": "/", "query": {}, "semantic_page_context": {"page_kind": "generic"}},
        working_context={},
        dialog_state={},
        followup_hint={},
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert decision is not None
    assert decision.stop_reason == "action_first_auto_execute"
    assert decision.auto_execute_actions[0].action_type == "create_discovery_job"
    assert decision.auto_execute_actions[0].params["cidr"] == "192.168.10.0/24"


def test_run_model_once_returns_mock_decision_without_direct_branch(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(messages=[SimpleNamespace(role="user", message_type="text", content="你是谁")])
    user = SimpleNamespace(role="admin")

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "mock")

    decision = haor_agent_service._run_model_once(
        session=session,
        user=user,
        page_context={"pathname": "/assets/asset-1", "query": {}, "asset_id": "asset-1"},
        browser_context={
            "pathname": "/assets/asset-1",
            "query": {},
            "asset_id": "asset-1",
            "semantic_page_context": {"page_kind": "asset_detail"},
        },
        browser_runtime={},
        working_context={"asset_id": "asset-1"},
        dialog_state={},
        followup_hint={},
        tool_traces=[],
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert decision.conversation_state == "answer"
    assert decision.stop_reason == "mock_mode"
    assert decision.proposed_write_actions == []
    assert decision.auto_execute_actions == []


def test_run_agent_loop_falls_back_to_action_first_decision_when_model_returns_non_json(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class _FakeProvider:
        def generate(self, _request):
            return "好的，我会开始扫描 192.168.10.0/24 网段，并实时同步进度。"

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "custom_proxy")
    monkeypatch.setattr(haor_agent_service, "match_registered_playbook", lambda **kwargs: None)
    monkeypatch.setattr(
        haor_agent_service,
        "_build_runtime_provider",
        lambda **kwargs: SimpleNamespace(provider=_FakeProvider()),
    )

    decision, tool_traces = haor_agent_service._run_agent_loop(
        _FakeUnitDB(),
        session=SimpleNamespace(messages=[SimpleNamespace(role="user", message_type="text", content="帮我扫描 192.168.10.0/24 网段，并实时告诉我进度")]),
        user=SimpleNamespace(role="admin"),
        page_context={"pathname": "/", "query": {}},
        browser_context={"pathname": "/", "query": {}, "semantic_page_context": {"page_kind": "generic"}},
        browser_runtime={},
        working_context={},
        dialog_state={},
        followup_hint={},
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert tool_traces == []
    assert decision.stop_reason == "action_first_auto_execute"
    assert decision.auto_execute_actions[0].action_type == "create_discovery_job"
    assert decision.auto_execute_actions[0].params["cidr"] == "192.168.10.0/24"


def test_run_agent_loop_falls_back_when_model_returns_schema_invalid_json(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class _FakeProvider:
        def generate(self, _request):
            return """
            {
              "reply_markdown": "我来处理。",
              "conversation_state": "answer",
              "read_tool_calls": "oops"
            }
            """

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "custom_proxy")
    monkeypatch.setattr(haor_agent_service, "match_registered_playbook", lambda **kwargs: None)
    monkeypatch.setattr(
        haor_agent_service,
        "_build_runtime_provider",
        lambda **kwargs: SimpleNamespace(
            provider_name="custom_proxy",
            resolved_base_url="https://example.test/v1",
            provider=SimpleNamespace(wire_api="responses", generate=_FakeProvider().generate),
        ),
    )

    decision, tool_traces = haor_agent_service._run_agent_loop(
        _FakeUnitDB(),
        session=SimpleNamespace(messages=[SimpleNamespace(role="user", message_type="text", content="帮我扫描 192.168.10.0/24 网段")]),
        user=SimpleNamespace(role="admin"),
        page_context={"pathname": "/", "query": {}},
        browser_context={"pathname": "/", "query": {}, "semantic_page_context": {"page_kind": "generic"}},
        browser_runtime={},
        working_context={},
        dialog_state={},
        followup_hint={},
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert tool_traces == []
    assert decision.stop_reason == "action_first_auto_execute"
    assert decision.auto_execute_actions[0].action_type == "create_discovery_job"


def test_run_model_once_retries_custom_proxy_with_chat_completions_on_contract_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(messages=[SimpleNamespace(role="user", message_type="text", content="继续")])
    user = SimpleNamespace(role="admin")
    build_calls: list[tuple[str | None, bool]] = []

    def _fake_build_runtime_provider(*, wire_api_override=None, chat_json_mode=False):  # type: ignore[no-untyped-def]
        build_calls.append((wire_api_override, chat_json_mode))
        if wire_api_override == "chat_completions":
            return SimpleNamespace(
                provider_name="custom_proxy",
                resolved_base_url="https://example.test/v1",
                provider=SimpleNamespace(
                    wire_api="chat_completions",
                    generate=lambda _request: '{"reply_markdown":"已恢复继续分析。","conversation_state":"answer"}',
                ),
            )
        return SimpleNamespace(
            provider_name="custom_proxy",
            resolved_base_url="https://example.test/v1",
            provider=SimpleNamespace(
                wire_api="responses",
                generate=lambda _request: '{"reply_markdown":"我来处理。","conversation_state":"answer","read_tool_calls":"oops"}',
            ),
        )

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "custom_proxy")
    monkeypatch.setattr(haor_agent_service, "_build_runtime_provider", _fake_build_runtime_provider)

    decision = haor_agent_service._run_model_once(
        session=session,
        user=user,
        page_context={"pathname": "/", "query": {}},
        browser_context={"pathname": "/", "query": {}, "semantic_page_context": {"page_kind": "generic"}},
        browser_runtime={},
        working_context={},
        dialog_state={},
        followup_hint={"reply_kind": "affirm", "raw_user_reply": "继续"},
        tool_traces=[],
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert decision.reply_markdown == "已恢复继续分析。"
    assert build_calls == [(None, False), ("chat_completions", True)]


def test_build_action_first_fallback_decision_resumes_from_recent_resume_hint() -> None:
    user = SimpleNamespace(role="admin")
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(
                payload_json={
                    "resume_hint": {
                        "kind": "post_verify_analysis",
                        "working_context": {"asset_id": "asset-1"},
                        "preferred_read_tools": [
                            {"tool_name": "list_asset_risks", "arguments": {"asset_id": "asset-1", "limit": 10}}
                        ],
                        "suggested_reply_label": "分析验证结果",
                    }
                }
            )
        ]
    )

    decision = haor_agent_service._build_action_first_fallback_decision(
        content="继续",
        user=user,
        page_context={"pathname": "/", "query": {}},
        browser_context={"pathname": "/", "query": {}, "semantic_page_context": {"page_kind": "generic"}},
        working_context={},
        dialog_state={},
        followup_hint={"reply_kind": "affirm", "raw_user_reply": "继续"},
        allow_write_plans=True,
        allow_auto_execute_actions=True,
        session=session,
        tool_traces=[],
    )

    assert decision is not None
    assert decision.stop_reason == "resume_hint_read"
    assert decision.read_tool_calls[0].tool_name == "list_asset_risks"
    assert decision.read_tool_calls[0].arguments["asset_id"] == "asset-1"


def test_build_resume_hint_read_decision_prefers_review_followup_phrase() -> None:
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(
                payload_json={
                    "resume_hint": {
                        "kind": "post_remediation_review",
                        "working_context": {"asset_id": "asset-1", "task_id": "task-1"},
                        "preferred_read_tools": [
                            {"tool_name": "get_remediation_asset", "arguments": {"asset_id": "asset-1"}},
                            {"tool_name": "get_task_detail", "arguments": {"task_id": "task-1"}},
                        ],
                        "suggested_reply_label": "复盘修复结果",
                    }
                }
            )
        ]
    )

    decision = haor_agent_service._build_resume_hint_read_decision(
        content="继续，复盘这次自动修复结果",
        session=session,
        working_context={},
        tool_traces=[],
        allow_extended_resume=True,
    )

    assert decision is not None
    assert decision.stop_reason == "resume_hint_read"
    assert [item.tool_name for item in decision.read_tool_calls] == ["get_remediation_asset", "get_task_detail"]


def test_should_skip_preflight_clarification_for_scan_resume_followup() -> None:
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(
                payload_json={
                    "resume_hint": {
                        "kind": "post_scan_analysis",
                        "working_context": {"task_id": "task-1"},
                        "preferred_read_tools": [
                            {"tool_name": "get_task_detail", "arguments": {"task_id": "task-1"}},
                        ],
                        "suggested_reply_label": "分析扫描结果",
                    }
                }
            )
        ]
    )

    assert (
        haor_agent_service._should_skip_preflight_clarification(
            "继续分析扫描结果",
            session=session,
        )
        is True
    )


def test_resolve_effective_working_context_reuses_resume_hint_for_extended_scan_followup() -> None:
    session = SimpleNamespace(
        working_context_json={},
        messages=[
            SimpleNamespace(
                payload_json={
                    "resume_hint": {
                        "kind": "post_scan_analysis",
                        "working_context": {"task_id": "task-1", "source": "task_followup"},
                        "preferred_read_tools": [
                            {"tool_name": "get_task_detail", "arguments": {"task_id": "task-1"}},
                        ],
                        "suggested_reply_label": "分析扫描结果",
                    }
                }
            )
        ],
    )

    resolved = haor_agent_service._resolve_effective_working_context(
        db=_FakeLookupDB(),
        session=session,
        content="继续分析扫描结果",
        page_context={"pathname": "/discovery", "query": {}},
        browser_context={"pathname": "/discovery", "query": {}},
        dialog_state={},
        followup_hint={"reply_kind": "unknown", "raw_user_reply": "继续分析扫描结果"},
    )

    assert resolved["task_id"] == "task-1"
    assert resolved["primary_target"]["task_id"] == "task-1"


def test_build_resume_hint_summary_decision_summarizes_scan_assets() -> None:
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(
                payload_json={
                    "resume_hint": {
                        "kind": "post_scan_analysis",
                        "working_context": {"task_id": "task-1"},
                        "preferred_read_tools": [
                            {"tool_name": "list_assets", "arguments": {"keyword": "192.168.130.0/24", "limit": 5}},
                            {"tool_name": "get_task_detail", "arguments": {"task_id": "task-1"}},
                        ],
                        "suggested_reply_label": "分析扫描结果",
                    }
                }
            )
        ]
    )

    decision = haor_agent_service._build_resume_hint_summary_decision(
        session=session,
        tool_traces=[
            {
                "tool_name": "list_assets",
                "arguments": {"keyword": "192.168.130.0/24", "limit": 5},
                "ok": True,
                "result": {
                    "items": [
                        {"asset_id": "asset-1", "ip": "192.168.130.138", "hostname": "target-1", "os_name": "Ubuntu"},
                        {"asset_id": "asset-2", "ip": "192.168.130.139", "hostname": "target-2", "os_name": "Debian"},
                    ],
                    "total": 2,
                },
            },
            {
                "tool_name": "get_task_detail",
                "arguments": {"task_id": "task-1"},
                "ok": True,
                "result": {"task_id": "task-1", "status": "success", "message": "扫描流水线完成"},
            },
        ],
    )

    assert decision is not None
    assert decision.stop_reason == "resume_hint_scan_summary"
    assert decision.conversation_state == "answer"
    assert "本次扫描共关联到 2 台资产" in decision.reply_markdown
    assert "192.168.130.138 / target-1 / Ubuntu" in decision.reply_markdown


def test_build_resume_hint_read_decision_does_not_hijack_maintenance_window_followup() -> None:
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(
                payload_json={
                    "resume_hint": {
                        "kind": "post_remediation_review",
                        "working_context": {"asset_id": "asset-1", "task_id": "task-1"},
                        "preferred_read_tools": [
                            {"tool_name": "get_remediation_asset", "arguments": {"asset_id": "asset-1"}},
                        ],
                        "suggested_reply_label": "复盘修复结果",
                    }
                }
            )
        ]
    )

    decision = haor_agent_service._build_resume_hint_read_decision(
        content="maintenance_window_id 是 mw-e2e-20260327，请继续自动修复",
        session=session,
        working_context={},
        tool_traces=[],
        allow_extended_resume=True,
    )

    assert decision is None


def test_build_action_first_fallback_decision_clarifies_short_resume_without_context() -> None:
    user = SimpleNamespace(role="admin")

    decision = haor_agent_service._build_action_first_fallback_decision(
        content="继续",
        user=user,
        page_context={"pathname": "/", "query": {}},
        browser_context={"pathname": "/", "query": {}, "semantic_page_context": {"page_kind": "generic"}},
        working_context={},
        dialog_state={},
        followup_hint={"reply_kind": "affirm", "raw_user_reply": "继续"},
        allow_write_plans=True,
        allow_auto_execute_actions=True,
        session=SimpleNamespace(messages=[]),
        tool_traces=[],
    )

    assert decision is not None
    assert decision.conversation_state == "clarifying"
    assert "稳定承接上一轮" in decision.reply_markdown


def test_run_agent_loop_prefers_resume_hint_review_before_playbook(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(
        messages=[
            SimpleNamespace(
                role="assistant",
                message_type="task_update",
                content="修复任务已完成",
                payload_json={
                    "resume_hint": {
                        "kind": "post_remediation_review",
                        "working_context": {"asset_id": "asset-1", "task_id": "task-1"},
                        "preferred_read_tools": [
                            {"tool_name": "get_remediation_asset", "arguments": {"asset_id": "asset-1"}},
                        ],
                        "suggested_reply_label": "复盘修复结果",
                    }
                },
            ),
            SimpleNamespace(role="user", message_type="text", content="继续，复盘这次自动修复结果"),
        ],
        working_context_json={"asset_id": "asset-1"},
    )
    user = SimpleNamespace(role="admin")
    read_calls: list[tuple[str, dict[str, object]]] = []
    model_flags: list[tuple[bool, bool]] = []

    monkeypatch.setattr(
        haor_agent_service,
        "match_registered_playbook",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("resume priority should bypass remediation playbook")),
    )
    monkeypatch.setattr(
        haor_agent_service,
        "_execute_read_tool",
        lambda db, *, tool_name, arguments: read_calls.append((tool_name, arguments)) or {"asset_id": "asset-1", "status": "ready"},
    )
    monkeypatch.setattr(
        haor_agent_service,
        "_run_model_once",
        lambda **kwargs: model_flags.append((kwargs["allow_write_plans"], kwargs["allow_auto_execute_actions"]))
        or haor_agent_service._AgentModelDecision(
            reply_markdown="我已读取修复结果。",
            conversation_state="answer",
        ),
    )

    decision, tool_traces = haor_agent_service._run_agent_loop(
        _FakeUnitDB(),
        session=session,
        user=user,
        page_context={"pathname": "/assets/asset-1", "asset_id": "asset-1", "query": {}},
        browser_context={"pathname": "/assets/asset-1", "asset_id": "asset-1", "query": {}, "semantic_page_context": {"page_kind": "generic"}},
        browser_runtime={},
        working_context={"asset_id": "asset-1"},
        dialog_state={},
        followup_hint={},
        allow_write_plans=True,
        allow_auto_execute_actions=True,
    )

    assert decision.reply_markdown == "我已读取修复结果。"
    assert read_calls == [("get_remediation_asset", {"asset_id": "asset-1"})]
    assert tool_traces[0]["tool_name"] == "get_remediation_asset"
    assert model_flags == [(False, False)]


def test_reconcile_running_session_state_restores_active_after_canceled_task(monkeypatch) -> None:
    session = SimpleNamespace(
        id="session-1",
        status="running",
        last_task_id="task-1",
        pending_plan_json={"reply_markdown": "待执行"},
        dialog_state_json={"status": "awaiting_user_input"},
        browser_runtime_json={"phase": "awaiting_ui_feedback"},
        working_context_json={"asset_id": "asset-1"},
        messages=[],
        updated_at=None,
    )

    monkeypatch.setattr(
        haor_agent_service,
        "get_task_run",
        lambda db, task_id: SimpleNamespace(
            id=task_id,
            status=TaskExecutionStatus.CANCELED,
            task_type=TaskType.AGENT_ORCHESTRATE,
            scope_type="agent_session",
            scope_id="session-1",
        ),
    )

    interrupted = {}
    monkeypatch.setattr(
        haor_agent_service,
        "_append_interrupted_task_message",
        lambda db, *, session, task_id, source: interrupted.update({"task_id": task_id, "source": source}),
    )

    changed = haor_agent_service._reconcile_running_session_state(SimpleNamespace(add=lambda *_: None), session=session)

    assert changed is True
    assert session.status == "active"
    assert session.pending_plan_json == {}
    assert session.dialog_state_json == {}
    assert session.browser_runtime_json == {}
    assert session.working_context_json["asset_id"] == "asset-1"
    assert interrupted == {"task_id": "task-1", "source": "session_reconcile"}


def test_reconcile_running_session_state_keeps_live_orchestrate_task_running(monkeypatch) -> None:
    session = SimpleNamespace(
        id="session-1",
        status="running",
        last_task_id="task-1",
        pending_plan_json={},
        dialog_state_json={},
        browser_runtime_json={"phase": "running"},
        working_context_json={"asset_id": "asset-1"},
        messages=[],
        updated_at=None,
    )

    monkeypatch.setattr(
        haor_agent_service,
        "get_task_run",
        lambda db, task_id: SimpleNamespace(
            id=task_id,
            status=TaskExecutionStatus.RUNNING,
            task_type=TaskType.AGENT_ORCHESTRATE,
            scope_type="agent_session",
            scope_id="session-1",
        ),
    )

    changed = haor_agent_service._reconcile_running_session_state(SimpleNamespace(add=lambda *_: None), session=session)

    assert changed is False
    assert session.status == "running"
    assert session.browser_runtime_json["phase"] == "running"


def test_match_registered_playbook_routes_blocked_goal_to_secure_ssh_input() -> None:
    current_goal = SimpleNamespace(
        id="goal-1",
        goal_kind="install_runner",
        blocked_reason="当前 SSH 凭据尚未确认管理员授权",
        progress_json={
            "blockers": [
                {
                    "blocker_code": "authorization_unconfirmed",
                    "blocker_message": "当前 SSH 凭据尚未确认管理员授权",
                }
            ]
        },
    )

    decision = agent_playbook_service.match_registered_playbook(
        content="继续",
        page_context={"pathname": "/assets", "asset_id": None, "query": {}},
        browser_context={
            "semantic_page_context": {
                "selected_rows": [
                    {"asset_id": "asset-1", "label": "192.168.1.10"},
                    {"asset_id": "asset-2", "label": "192.168.1.11"},
                ]
            }
        },
        working_context={},
        current_goal=current_goal,
    )

    assert decision is not None
    assert decision.playbook_id == "configure_ssh_credential"
    assert decision.proposed_write_actions[0]["action_type"] == "configure_ssh_credential"
    assert decision.proposed_write_actions[0]["params"]["resume_goal_id"] == "goal-1"
    assert decision.proposed_write_actions[0]["params"]["resume_action"]["action_type"] == "install_runner"
    assert decision.proposed_write_actions[0]["params"]["asset_ids"] == ["asset-1", "asset-2"]


def test_build_runtime_snapshot_locks_input_for_secure_input_phase() -> None:
    session = SimpleNamespace(
        status="active",
        browser_runtime_json={
            "phase": "awaiting_secure_input",
            "pending_secure_input": {
                "asset_id": "asset-1",
                "asset_labels": ["资产 asset-1"],
                "resume_action": {
                    "action_type": "install_runner",
                    "title": "为资产 asset-1 安装 Runner",
                    "reason": "继续原目标",
                    "params": {"asset_id": "asset-1"},
                },
            },
        },
        agent_state_json={},
        pending_plan_json={},
        current_goal=None,
        last_task_id=None,
        messages=[],
    )

    snapshot = haor_agent_service._build_runtime_snapshot(session)

    assert snapshot.phase == "awaiting_secure_input"
    assert snapshot.input_state == "locked"
    assert snapshot.input_block_reason == "pending_sensitive_input"
    assert snapshot.active_skill_id == "configure_ssh_credential"


def test_normalize_result_payload_blockers_recovers_ssh_code_from_unknown_blocker() -> None:
    blockers = haor_agent_service._normalize_result_payload_blockers(
        {
            "blockers": [
                {
                    "code": "unknown_blocker",
                    "message": "当前资产未配置 SSH 管理员凭据",
                    "scope": "global",
                    "blocking": "hard",
                }
            ]
        }
    )

    assert blockers == [
        {
            "code": "missing_ssh_credential",
            "message": "当前资产未配置 SSH 管理员凭据",
            "blocker_category": "ssh",
            "scope": "global",
            "blocking": "hard",
            "stage_code": None,
            "step_id": None,
        }
    ]


def test_build_remediation_guidance_payload_prefers_maintenance_window_input_for_policy_blocker() -> None:
    payload = haor_agent_service._build_remediation_guidance_payload(
        asset_id="asset-1",
        blockers=[
            {
                "code": "maintenance_window_required",
                "message": "当前阶段包含高风险步骤，请先填写 maintenance_window_id 后再正式执行",
                "blocker_category": "policy",
            }
        ],
    )

    assert payload["blocker_categories"] == ["policy"]
    assert payload["recommended_action"]["kind"] == "open_maintenance_window_input"
    assert payload["recommended_action"]["label"] == "填写维护窗口并继续自动修复"
    assert payload["alternative_action"]["kind"] == "navigate"
    assert payload["alternative_action"]["pathname"] == "/remediation/asset-1"
    assert payload["post_verify_action"] == "maintenance_window_required"


def test_handle_secure_input_step_reports_remaining_remediation_blockers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(
        id="session-1",
        agent_id="haor",
        status="active",
        route_context_json={"pathname": "/assets", "query": {}, "asset_id": "asset-1"},
        working_context_json={"asset_id": "asset-1"},
        dialog_state_json={},
        pending_plan_json={},
        browser_runtime_json={},
        agent_state_json={},
        current_goal=None,
        current_goal_id="goal-1",
        last_task_id="task-orchestrate-1",
        messages=[],
        created_at=datetime.now(UTC),
        updated_at=None,
    )
    db = _FakeMessageDB(session)
    synced_goal: dict[str, object] = {}

    monkeypatch.setattr(
        haor_agent_service,
        "_execute_auto_actions",
        lambda *args, **kwargs: [
            {
                "action_type": "create_or_resume_remediation_session",
                "title": "继续修复会话 remediation-session-1",
                "status": "success",
                "summary": "当前未自动执行：当前主机尚未安装 Host Runner",
                "params": {"asset_id": "asset-1", "submit_if_ready": True},
                "payload": {
                    "asset_id": "asset-1",
                    "session_id": "remediation-session-1",
                    "execution_ready": False,
                    "blocked_reasons": ["当前主机尚未安装 Host Runner"],
                    "blocker_codes": ["runner_not_installed"],
                    "blockers": [
                        {
                            "code": "runner_not_installed",
                            "message": "当前主机尚未安装 Host Runner",
                            "scope": "asset",
                            "blocking": "hard",
                        }
                    ],
                    "submitted_task_id": None,
                },
                "child_task_id": None,
            }
        ],
    )
    monkeypatch.setattr(haor_agent_service, "resume_agent_goal_binding", lambda *args, **kwargs: None)
    monkeypatch.setattr(haor_agent_service, "_emit_session_snapshot", lambda *args, **kwargs: None)

    def _fake_sync_goal(_db, _session, **kwargs):  # type: ignore[no-untyped-def]
        synced_goal.update(kwargs)
        return None

    monkeypatch.setattr(haor_agent_service, "_sync_current_goal_state", _fake_sync_goal)

    result = haor_agent_service._handle_secure_input_step(
        db,
        session=session,
        user=SimpleNamespace(id="user-1"),
        browser_context={"pathname": "/assets", "query": {}, "asset_id": "asset-1"},
        current_browser_runtime={
            "phase": "awaiting_secure_input",
            "current_objective": "为资产 asset-1 配置 SSH 凭据",
            "objective_kind": "configure_ssh_credential",
            "last_user_intent": "配置 SSH 凭据",
            "pending_secure_input": {
                "kind": "ssh_credential",
                "mode": "same_credential_batch",
                "asset_id": "asset-1",
                "asset_ids": ["asset-1", "asset-2"],
                "asset_labels": ["资产 asset-1", "资产 asset-2"],
                "resume_goal_id": "goal-1",
                "resume_action": {
                    "action_type": "create_or_resume_remediation_session",
                    "title": "继续修复会话 remediation-session-1",
                    "reason": "SSH 凭据验证成功后继续修复",
                    "params": {"asset_id": "asset-1", "submit_if_ready": True},
                },
                "auto_verify": True,
                "auto_resume": True,
            },
        },
        ui_action_results=[
            {
                "detail_json": {
                    "kind": "ssh_credential_batch",
                    "results": [
                        {
                            "asset_id": "asset-1",
                            "saved": True,
                            "verified": True,
                        },
                        {
                            "asset_id": "asset-2",
                            "saved": True,
                            "verified": True,
                        },
                    ],
                }
            }
        ],
        platform_url="http://localhost:3000",
    )

    assert result is not None
    message_objects = [item for item in db.added if getattr(item, "content", None)]
    assert message_objects
    content = message_objects[-1].content
    assert "SSH 凭据批量处理完成" in content
    assert "当前主机尚未安装 Host Runner" in content
    assert "原修复目标仍未继续执行" in content
    assert session.status == "active"
    assert session.agent_state_json["execution"]["stage"] == "blocked"
    assert synced_goal["status_override"] == "blocked"
    assert "Host Runner" in str(synced_goal["blocked_reason"])
    goal_blockers = synced_goal["goal_blockers"]
    assert isinstance(goal_blockers, list)
    assert goal_blockers[0]["code"] == "runner_not_installed"


def test_handle_secure_input_step_refreshes_host_facts_before_resuming_remediation(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(
        id="session-1",
        agent_id="haor",
        status="active",
        route_context_json={"pathname": "/assets", "query": {}, "asset_id": "asset-1"},
        working_context_json={"asset_id": "asset-1"},
        dialog_state_json={},
        pending_plan_json={},
        browser_runtime_json={},
        agent_state_json={},
        current_goal=None,
        current_goal_id="goal-1",
        last_task_id="task-orchestrate-1",
        messages=[],
        created_at=datetime.now(UTC),
        updated_at=None,
    )
    db = _FakeMessageDB(session)
    synced_goal: dict[str, object] = {}
    refresh_calls: list[str] = []
    followup_calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        haor_agent_service,
        "_execute_auto_actions",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should queue collection refresh before resuming remediation")),
    )
    monkeypatch.setattr(haor_agent_service, "resume_agent_goal_binding", lambda *args, **kwargs: None)
    monkeypatch.setattr(haor_agent_service, "_emit_session_snapshot", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        haor_agent_service,
        "_queue_asset_collection_refresh",
        lambda _db, *, asset_id: refresh_calls.append(asset_id) or "task-collect-1",
    )
    monkeypatch.setattr(
        haor_agent_service,
        "_enqueue_secure_refresh_resume_followup",
        lambda **kwargs: followup_calls.append(kwargs),
    )

    def _fake_sync_goal(_db, _session, **kwargs):  # type: ignore[no-untyped-def]
        synced_goal.update(kwargs)
        return None

    monkeypatch.setattr(haor_agent_service, "_sync_current_goal_state", _fake_sync_goal)

    result = haor_agent_service._handle_secure_input_step(
        db,
        session=session,
        user=SimpleNamespace(id="user-1"),
        browser_context={"pathname": "/assets", "query": {}, "asset_id": "asset-1"},
        current_browser_runtime={
            "phase": "awaiting_secure_input",
            "current_objective": "为资产 asset-1 配置 SSH 凭据",
            "objective_kind": "configure_ssh_credential",
            "last_user_intent": "配置 SSH 凭据",
            "pending_secure_input": {
                "kind": "ssh_credential",
                "mode": "single_asset",
                "asset_id": "asset-1",
                "asset_ids": ["asset-1"],
                "asset_labels": ["资产 asset-1"],
                "resume_goal_id": "goal-1",
                "resume_action": {
                    "action_type": "create_or_resume_remediation_session",
                    "title": "继续修复会话 remediation-session-1",
                    "reason": "SSH 凭据验证成功后继续修复",
                    "params": {"asset_id": "asset-1", "submit_if_ready": True},
                },
                "auto_verify": True,
                "auto_resume": True,
            },
        },
        ui_action_results=[
            {
                "detail_json": {
                    "kind": "ssh_credential_single",
                    "asset_id": "asset-1",
                    "saved": True,
                    "verified": True,
                    "auth_type": "password",
                    "username": "root",
                }
            }
        ],
        platform_url="http://localhost:3000",
    )

    assert result is not None
    assert refresh_calls == ["asset-1"]
    assert followup_calls == [
        {
            "session_id": "session-1",
            "refresh_task_id": "task-collect-1",
            "action": {
                "action_type": "create_or_resume_remediation_session",
                "title": "继续修复会话 remediation-session-1",
                "reason": "SSH 凭据验证成功后继续修复",
                "params": {"asset_id": "asset-1", "submit_if_ready": True},
            },
            "asset_id": "asset-1",
        }
    ]
    assert session.status == "running"
    assert session.agent_state_json["execution"]["stage"] == "watching_task"
    assert session.agent_state_json["watch"]["primary_task_id"] == "task-collect-1"
    message_objects = [item for item in db.added if getattr(item, "content", None)]
    assert message_objects
    content = message_objects[-1].content
    assert "正在通过 SSH 刷新主机信息；刷新完成后会重新评估修复条件" in content
    assert session.agent_state_json["execution"]["waiting_for"] == "等待主机事实刷新完成"
    payload_json = message_objects[-1].payload_json
    assert payload_json["secure_input_result"]["post_verify_action"] == "refresh_and_resume"
    assert payload_json["secure_input_result"]["refresh_task_id"] == "task-collect-1"
    assert synced_goal["status_override"] == "active"
