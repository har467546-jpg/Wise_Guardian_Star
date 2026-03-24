from __future__ import annotations

from datetime import UTC, datetime
import httpx
from types import SimpleNamespace

from app.db.models.enums import TaskExecutionStatus, TaskType
from app.schemas.agent import AgentMessageCreateRequest
from app.services import haor_agent_service


class _FakeUnitDB:
    def add(self, value) -> None:
        if getattr(value, "id", None) is None:
            value.id = f"fake-{id(value)}"
        if getattr(value, "created_at", None) is None:
            value.created_at = datetime.now(UTC)

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


def test_append_or_stream_assistant_message_scrubs_reply_stream_output_before_emitting(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class _FakeProvider:
        def stream_generate(self, _request):
            yield '<think>用户只是打了个招呼"你好"，confirmed_reply_draft 已经准备好了回复。'
            yield "working_context 和 tool_trace_summary 都是空的，说明没有需要调用工具。"
            yield "我需要把 confirmed_reply_draft 直接整理输出给用户。</think>\n\n你好！有什么我可以帮助你的吗？"

    events: list[dict] = []
    session = SimpleNamespace(id="session-1", updated_at=None)

    monkeypatch.setattr(haor_agent_service, "_runtime_provider_mode", lambda: "custom_proxy")
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
        session=session,
        content="继续看这个资产",
        page_context={"pathname": "/assets/asset-2", "query": {}, "asset_id": "asset-2", "finding_id": None, "task_id": None},
    )

    assert working_context["asset_id"] == "asset-2"
    assert working_context["primary_target"]["asset_id"] == "asset-2"


def test_resolve_working_context_restores_dialog_snapshot_for_affirm_followup() -> None:
    session = SimpleNamespace(working_context_json={})

    working_context = haor_agent_service._resolve_working_context_for_message(
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
    monkeypatch.setattr(
        haor_agent_service,
        "_build_runtime_provider",
        lambda: SimpleNamespace(provider=_FakeProvider()),
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
