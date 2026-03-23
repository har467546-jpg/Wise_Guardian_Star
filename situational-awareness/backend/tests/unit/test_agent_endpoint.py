from datetime import datetime, timedelta, timezone
import threading
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_current_user
from app.api.v1.endpoints import agent as agent_endpoint
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models.asset import Asset
from app.db.models.agent_session import AgentSession
from app.db.models.enums import AssetStatus, TaskExecutionStatus, TaskType, UserRole
from app.db.models.task_run import TaskRun
from app.db.models.user import User
import app.db.session as db_session_module
import app.main as app_main_module
from app.main import create_app
from app.services import haor_agent_service

SessionLocal = db_session_module.SessionLocal
engine = db_session_module.engine
_OPEN_TEST_CLIENTS: list[TestClient] = []
_OPEN_TEST_ENGINES = []


@compiles(JSONB, "sqlite")
def _compile_jsonb_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "JSON"


@compiles(INET, "sqlite")
def _compile_inet_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "TEXT"


@compiles(CIDR, "sqlite")
def _compile_cidr_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "TEXT"


def _override_user(role: UserRole, user_id: str):
    def _resolver():
        return SimpleNamespace(id=user_id, role=role, is_active=True)

    return _resolver


def _install_test_database() -> None:
    global SessionLocal, engine

    test_engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    test_session_local = sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
        class_=Session,
    )

    db_session_module.engine = test_engine
    db_session_module.SessionLocal = test_session_local
    app_main_module.engine = test_engine
    app_main_module.SessionLocal = test_session_local
    agent_endpoint.SessionLocal = test_session_local

    engine = test_engine
    SessionLocal = test_session_local
    _OPEN_TEST_ENGINES.append(test_engine)


@pytest.fixture(autouse=True)
def _cleanup_test_clients_and_engines():  # type: ignore[no-untyped-def]
    yield
    while _OPEN_TEST_CLIENTS:
        _OPEN_TEST_CLIENTS.pop().close()
    while _OPEN_TEST_ENGINES:
        _OPEN_TEST_ENGINES.pop().dispose()


def _build_client(role: UserRole = UserRole.ADMIN) -> tuple[TestClient, str]:
    _install_test_database()
    Base.metadata.create_all(bind=engine)
    user_id = str(uuid4())
    with SessionLocal() as db:
        db.add(
            User(
                id=user_id,
                username=f"user-{user_id[:8]}",
                email=f"{user_id[:8]}@example.test",
                password_hash="hashed",
                role=role,
                is_active=True,
            )
        )
        db.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = _override_user(role, user_id)
    client = TestClient(app)
    _OPEN_TEST_CLIENTS.append(client)
    return client, user_id


def _build_ws_token(user_id: str, role: UserRole) -> str:
    return create_access_token(subject=user_id, extra={"role": role.value})


def _receive_ws_events_until(websocket, *, stop_type: str, limit: int = 24) -> list[dict]:  # type: ignore[no-untyped-def]
    events: list[dict] = []
    for _ in range(limit):
        item = websocket.receive_json()
        events.append(item)
        if item["type"] == stop_type:
            break
    return events


def _page_context(
    *,
    pathname: str = "/",
    asset_id: str | None = None,
    finding_id: str | None = None,
    task_id: str | None = None,
) -> dict:
    return {
        "pathname": pathname,
        "query": {},
        "asset_id": asset_id,
        "finding_id": finding_id,
        "task_id": task_id,
    }


def _browser_context(
    *,
    pathname: str = "/",
    asset_id: str | None = None,
    finding_id: str | None = None,
    task_id: str | None = None,
) -> dict:
    page_context = _page_context(pathname=pathname, asset_id=asset_id, finding_id=finding_id, task_id=task_id)
    return {
        **page_context,
        "origin": "http://testserver",
        "title": "Test Page",
        "selected_entities": [],
        "open_panels": [],
        "forms": [],
        "visible_actions": [],
        "dom_snapshot": [],
    }


def test_get_haor_session_creates_and_recovers_latest_session(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    first = client.get("/api/v1/agent/haor/session")
    second = client.get("/api/v1/agent/haor/session")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["session_id"] == second.json()["session_id"]
    assert first.json()["messages"] == []


def test_get_haor_session_reconciles_stale_pending_ui_feedback_once(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    stale_at = datetime.now(timezone.utc) - timedelta(minutes=6)

    with SessionLocal() as db:
        db.add(
            AgentSession(
                id=str(uuid4()),
                agent_id="haor",
                user_id=user_id,
                status="active",
                route_context_json=_page_context(pathname="/"),
                working_context_json={},
                dialog_state_json={},
                pending_plan_json={},
                browser_runtime_json={
                    "phase": "awaiting_ui_feedback",
                    "pending_ui_actions": [
                        {
                            "action_id": "ui-stale-1",
                            "action_type": "navigate",
                            "target_node_id": "haor-node-2",
                            "retryable": False,
                        }
                    ],
                    "completed_ui_actions": [],
                    "last_ui_results": [],
                    "last_browser_context": _browser_context(pathname="/"),
                    "last_user_intent": "帮我扫描 192.168.130.0/24",
                },
                updated_at=stale_at,
                created_at=stale_at,
            )
        )
        db.commit()

    first = client.get("/api/v1/agent/haor/session")
    second = client.get("/api/v1/agent/haor/session")

    assert first.status_code == 200
    assert second.status_code == 200
    first_body = first.json()
    second_body = second.json()
    assert first_body["status"] == "active"
    assert first_body["browser_runtime_json"]["phase"] == "idle"
    assert first_body["browser_runtime_json"]["pending_ui_actions"] == []
    stale_messages = [item for item in first_body["messages"] if item["payload_json"].get("stale_ui_feedback")]
    assert len(stale_messages) == 1
    assert "已为你解除等待状态" in stale_messages[0]["content"]
    second_stale_messages = [item for item in second_body["messages"] if item["payload_json"].get("stale_ui_feedback")]
    assert len(second_stale_messages) == 1


def test_get_haor_session_reconciles_stale_pending_message_turn_once(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    stale_at = datetime.now(timezone.utc) - timedelta(minutes=3)

    with SessionLocal() as db:
        db.add(
            AgentSession(
                id=str(uuid4()),
                agent_id="haor",
                user_id=user_id,
                status="active",
                route_context_json=_page_context(pathname="/"),
                working_context_json={},
                dialog_state_json={},
                pending_plan_json={},
                browser_runtime_json={
                    "phase": "awaiting_agent_reply",
                    "current_message_request_id": "client-msg-stale-1",
                    "message_pending_since": stale_at.isoformat(),
                    "last_message_request_id": "client-msg-stale-1",
                    "last_message_ack_at": stale_at.isoformat(),
                    "last_browser_context": _browser_context(pathname="/"),
                    "last_user_intent": "帮我分析资产",
                },
                updated_at=stale_at,
                created_at=stale_at,
            )
        )
        db.commit()

    first = client.get("/api/v1/agent/haor/session")
    second = client.get("/api/v1/agent/haor/session")

    assert first.status_code == 200
    assert second.status_code == 200
    first_body = first.json()
    second_body = second.json()
    assert first_body["browser_runtime_json"]["phase"] == "idle"
    stale_messages = [item for item in first_body["messages"] if item["payload_json"].get("stale_message_turn")]
    assert len(stale_messages) == 1
    second_stale_messages = [item for item in second_body["messages"] if item["payload_json"].get("stale_message_turn")]
    assert len(second_stale_messages) == 1


def test_post_haor_message_returns_clarifying_message_when_context_missing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "帮我修复当前主机",
            "route_context": _page_context(pathname="/"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["pending_plan_json"] == {}
    assert body["messages"][-1]["message_type"] == "clarifying"
    assert "我还无法确认你指的是哪一个对象" in body["messages"][-1]["content"]
    assert body["messages"][-1]["proposed_write_actions"] == []


def test_post_haor_message_returns_mock_reply_without_plan(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "分析我当前页面上的对象",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["pending_plan_json"] == {}
    assert body["messages"][-1]["message_type"] == "text"
    assert body["messages"][-1]["payload_json"]["mock_mode"] is True
    assert body["working_context_json"]["asset_id"] == "asset-1"
    assert body["messages"][-1]["proposed_write_actions"] == []
    assert "模拟模式" in body["messages"][-1]["content"]
    assert "direct_reply" not in body["messages"][-1]["payload_json"]


def test_post_haor_message_persists_client_message_id(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "client_message_id": "client-msg-rest-1",
            "content": "分析我当前页面上的对象",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    user_message = next(item for item in body["messages"] if item["role"] == "user")
    assert user_message["payload_json"]["client_message_id"] == "client-msg-rest-1"


def test_post_haor_message_duplicate_client_message_id_only_runs_once_while_pending(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    started = threading.Event()
    release = threading.Event()
    call_count = {"value": 0}
    holder: dict[str, object] = {}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        started.set()
        assert release.wait(timeout=5)
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="已完成当前资产分析。",
                conversation_state="answer",
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    def _send_first() -> None:
        holder["response"] = client.post(
            "/api/v1/agent/haor/session/messages",
            json={
                "client_message_id": "client-msg-dup-1",
                "content": "分析我当前页面上的对象",
                "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
                "browser_context": _browser_context(pathname="/assets/asset-1", asset_id="asset-1"),
            },
        )

    thread = threading.Thread(target=_send_first)
    thread.start()
    assert started.wait(timeout=5)

    duplicate = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "client_message_id": "client-msg-dup-1",
            "content": "分析我当前页面上的对象",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
            "browser_context": _browser_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )

    release.set()
    thread.join(timeout=5)

    assert duplicate.status_code == 200
    duplicate_body = duplicate.json()
    assert duplicate_body["browser_runtime_json"]["current_message_request_id"] == "client-msg-dup-1"
    assert len([item for item in duplicate_body["messages"] if item["role"] == "user"]) == 1
    assert call_count["value"] == 1

    first = holder["response"]
    assert isinstance(first, httpx.Response)
    assert first.status_code == 200

    with SessionLocal() as db:
        session = db.query(AgentSession).filter(AgentSession.user_id == user_id).order_by(AgentSession.created_at.desc()).first()
        assert session is not None
        user_messages = [item for item in session.messages if item.role == "user"]
        assert len(user_messages) == 1


def test_post_haor_message_returns_409_when_another_message_turn_is_pending(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    started = threading.Event()
    release = threading.Event()
    call_count = {"value": 0}
    holder: dict[str, object] = {}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        started.set()
        assert release.wait(timeout=5)
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="已完成当前资产分析。",
                conversation_state="answer",
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    def _send_first() -> None:
        holder["response"] = client.post(
            "/api/v1/agent/haor/session/messages",
            json={
                "client_message_id": "client-msg-pending-1",
                "content": "分析我当前页面上的对象",
                "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
                "browser_context": _browser_context(pathname="/assets/asset-1", asset_id="asset-1"),
            },
        )

    thread = threading.Thread(target=_send_first)
    thread.start()
    assert started.wait(timeout=5)

    conflict = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "client_message_id": "client-msg-pending-2",
            "content": "分析另外一个资产",
            "page_context": _page_context(pathname="/assets/asset-2", asset_id="asset-2"),
            "browser_context": _browser_context(pathname="/assets/asset-2", asset_id="asset-2"),
        },
    )

    release.set()
    thread.join(timeout=5)

    assert conflict.status_code == 409
    assert "上一轮消息" in conflict.json()["detail"]
    assert call_count["value"] == 1

    first = holder["response"]
    assert isinstance(first, httpx.Response)
    assert first.status_code == 200

    with SessionLocal() as db:
        session = db.query(AgentSession).filter(AgentSession.user_id == user_id).order_by(AgentSession.created_at.desc()).first()
        assert session is not None
        user_messages = [item for item in session.messages if item.role == "user"]
        assert len(user_messages) == 1
        assert user_messages[0].payload_json["client_message_id"] == "client-msg-pending-1"


def test_model_clarifying_message_keeps_session_active(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="",
                conversation_state="clarifying",
                clarifying_question="我需要先知道具体的资产 ID，才能继续核对风险与修复上下文。",
                read_tool_calls=[],
                proposed_write_actions=[],
                needs_confirmation=False,
            ),
            [{"tool_name": "list_assets", "ok": True, "result": {"items": []}}],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "继续分析",
            "page_context": _page_context(pathname="/assets"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["pending_plan_json"] == {}
    assert body["messages"][-1]["message_type"] == "clarifying"
    assert "资产 ID" in body["messages"][-1]["content"]
    assert body["messages"][-1]["payload_json"]["tool_traces"][0]["tool_name"] == "list_assets"
    assert body["messages"][-1]["proposed_write_actions"] == []


def test_post_haor_message_uses_fixed_scan_followup_and_affirm_executes_scan(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    call_count = {"value": 0}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="当前未查询到该网段资产。",
                conversation_state="answer",
            ),
            [
                {
                    "tool_name": "list_assets",
                    "arguments": {"keyword": "192.168.10.0/24"},
                    "ok": True,
                    "result": {"items": [], "total": 0},
                }
            ],
        )

    class _FakeDelayResult:
        id = "celery-scan-task-1"

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)
    monkeypatch.setattr(
        haor_agent_service.run_asset_scan_task,
        "delay",
        lambda *args, **kwargs: _FakeDelayResult(),
    )

    first = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "帮我分析 192.168.10.0/24 资产的漏洞", "page_context": _page_context(pathname="/")},
    )
    second = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "是的", "page_context": _page_context(pathname="/")},
    )

    assert first.status_code == 200
    first_body = first.json()
    assert first_body["messages"][-1]["message_type"] == "clarifying"
    assert first_body["messages"][-1]["content"] == "未查询到 192.168.10.0/24 的现有资产。是否立即发起扫描？未指定标签时将使用默认标签。"
    assert first_body["dialog_state_json"]["candidate_write_context"]["action_type"] == "create_discovery_job"
    assert first_body["dialog_state_json"]["candidate_write_context"]["params"]["cidr"] == "192.168.10.0/24"
    assert first_body["dialog_state_json"]["candidate_write_context"]["allow_affirm_execute"] is True

    assert second.status_code == 200
    second_body = second.json()
    assert call_count["value"] == 1
    assert second_body["last_task_id"] is not None
    assert second_body["messages"][-2]["message_type"] == "action_update"
    assert "已自动执行 1 个低风险动作" in second_body["messages"][-2]["content"]
    assert second_body["messages"][-1]["message_type"] == "text"
    assert "已开始扫描 192.168.10.0/24，当前使用默认标签。" in second_body["messages"][-1]["content"]
    assert "继续帮你分析该网段资产的漏洞" in second_body["messages"][-1]["content"]
    assert "已自动执行 1 个低风险动作" not in second_body["messages"][-1]["content"]
    assert "task-" not in second_body["messages"][-1]["content"]

    with SessionLocal() as db:
        task = db.get(TaskRun, second_body["last_task_id"])
        session = db.get(AgentSession, second_body["session_id"])
        assert task is not None
        assert session is not None
        assert task.task_type == TaskType.ASSET_SCAN
        assert task.celery_task_id == "celery-scan-task-1"
        assert session.dialog_state_json == {}


def test_post_haor_message_can_continue_pending_clarification(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        dialog_state = kwargs.get("dialog_state") or {}
        followup_hint = kwargs.get("followup_hint") or {}
        if not dialog_state:
            return (
                haor_agent_service._AgentModelDecision(
                    reply_markdown="",
                    conversation_state="clarifying",
                    clarifying_question="是否继续查看任务详情以便分析？",
                    read_tool_calls=[
                        haor_agent_service._ReadToolCall(
                            tool_name="get_task_detail",
                            arguments={"task_id": "task-1"},
                        )
                    ],
                    needs_confirmation=False,
                    dialog_state_update=haor_agent_service._DialogState(
                        status="awaiting_user_input",
                        intent_kind="read_followup",
                        question_kind="confirm",
                        intent_summary="查看任务详情",
                        last_agent_question="是否继续查看任务详情以便分析？",
                        candidate_read_tools=[
                            haor_agent_service._ReadToolCall(
                                tool_name="get_task_detail",
                                arguments={"task_id": "task-1"},
                            )
                        ],
                        targets_snapshot={"working_context": {"task_id": "task-1"}},
                    ),
                ),
                [],
            )
        assert followup_hint["reply_kind"] == "affirm"
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="已继续查看任务 task-1 详情并完成分析。",
                conversation_state="answer",
                followup_resolution=haor_agent_service._FollowupResolution(status="resolved", summary="用户已确认继续"),
            ),
            [{"tool_name": "get_task_detail", "ok": True, "result": {"task_id": "task-1"}}],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    first = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "查看当前任务详情",
            "page_context": _page_context(pathname="/tasks/task-1", task_id="task-1"),
        },
    )
    second = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "继续",
            "page_context": _page_context(pathname="/tasks/task-1", task_id="task-1"),
        },
    )

    assert first.status_code == 200
    assert first.json()["messages"][-1]["message_type"] == "clarifying"
    assert second.status_code == 200
    body = second.json()
    assert body["status"] == "active"
    assert body["messages"][-1]["message_type"] == "text"
    assert body["working_context_json"]["task_id"] == "task-1"
    assert "已继续查看任务 task-1 详情并完成分析" in body["messages"][-1]["content"]


def test_post_haor_message_reuses_recent_focus_for_followup_question(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")
    call_count = {"value": 0}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        working_context = kwargs.get("working_context") or {}
        if call_count["value"] == 1:
            return (
                haor_agent_service._AgentModelDecision(
                    reply_markdown="已读取 192.168.10.230 的风险列表。",
                    conversation_state="answer",
                ),
                [
                    {
                        "tool_name": "list_asset_risks",
                        "arguments": {"asset_id": "asset-1"},
                        "ok": True,
                        "result": {"asset_id": "asset-1", "items": [{"finding_id": "finding-1"}], "total": 1},
                    }
                ],
            )
        assert working_context["asset_id"] == "asset-1"
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="最严重的是 finding-1。",
                conversation_state="answer",
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    first = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "帮我分析 192.168.10.0/24 网段中的资产漏洞", "page_context": _page_context(pathname="/")},
    )
    second = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "它最严重的漏洞是什么", "page_context": _page_context(pathname="/")},
    )

    assert first.status_code == 200
    assert first.json()["working_context_json"]["asset_id"] == "asset-1"
    assert second.status_code == 200
    body = second.json()
    assert body["messages"][-1]["message_type"] == "text"
    assert body["working_context_json"]["asset_id"] == "asset-1"
    assert "finding-1" in body["messages"][-1]["content"]


def test_post_haor_message_can_prepare_plan_from_recent_focus(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")
    call_count = {"value": 0}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        working_context = kwargs.get("working_context") or {}
        if call_count["value"] == 1:
            return (
                haor_agent_service._AgentModelDecision(
                    reply_markdown="已定位到目标资产。",
                    conversation_state="answer",
                ),
                [
                    {
                        "tool_name": "list_asset_risks",
                        "arguments": {"asset_id": "asset-1"},
                        "ok": True,
                        "result": {"asset_id": "asset-1", "items": [{"finding_id": "finding-1"}], "total": 1},
                    }
                ],
            )
        assert working_context["asset_id"] == "asset-1"
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="建议先创建修复会话。",
                conversation_state="plan",
                proposed_write_actions=[
                    haor_agent_service._ProposedWriteAction(
                        action_type="create_or_resume_remediation_session",
                        title="创建修复会话",
                        reason="已有明确资产上下文",
                        params={"asset_id": "asset-1"},
                    )
                ],
                needs_confirmation=True,
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    first = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "帮我看资产漏洞", "page_context": _page_context(pathname="/")},
    )
    second = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "生成修复计划", "page_context": _page_context(pathname="/")},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    body = second.json()
    assert body["status"] == "waiting_approval"
    assert body["messages"][-1]["message_type"] == "plan"
    assert body["working_context_json"]["asset_id"] == "asset-1"
    assert body["pending_plan_json"]["working_context"]["asset_id"] == "asset-1"


def test_post_haor_message_keeps_recent_focus_after_ai_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")
    call_count = {"value": 0}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        working_context = kwargs.get("working_context") or {}
        if call_count["value"] == 1:
            return (
                haor_agent_service._AgentModelDecision(
                    reply_markdown="已定位到目标资产。",
                    conversation_state="answer",
                ),
                [
                    {
                        "tool_name": "list_asset_risks",
                        "arguments": {"asset_id": "asset-1"},
                        "ok": True,
                        "result": {"asset_id": "asset-1", "items": [], "total": 0},
                    }
                ],
            )
        if call_count["value"] == 2:
            raise httpx.RequestError("boom")
        assert working_context["asset_id"] == "asset-1"
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="继续基于 asset-1 分析。",
                conversation_state="answer",
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    first = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "帮我定位目标资产", "page_context": _page_context(pathname="/")},
    )
    second = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "继续", "page_context": _page_context(pathname="/")},
    )
    third = client.post(
        "/api/v1/agent/haor/session/messages",
        json={"content": "生成修复计划", "page_context": _page_context(pathname="/")},
    )

    assert first.status_code == 200
    assert first.json()["working_context_json"]["asset_id"] == "asset-1"
    assert second.status_code == 200
    assert second.json()["messages"][-1]["message_type"] == "error"
    assert second.json()["working_context_json"]["asset_id"] == "asset-1"
    assert third.status_code == 200
    assert third.json()["messages"][-1]["message_type"] == "text"
    assert third.json()["working_context_json"]["asset_id"] == "asset-1"


def test_post_haor_message_can_cancel_pending_clarification(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")
    call_count = {"value": 0}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="",
                conversation_state="clarifying",
                clarifying_question="是否继续查看任务详情以便分析？",
                dialog_state_update=haor_agent_service._DialogState(
                    status="awaiting_user_input",
                    intent_kind="read_followup",
                    question_kind="confirm",
                    intent_summary="查看任务详情",
                    last_agent_question="是否继续查看任务详情以便分析？",
                    targets_snapshot={"working_context": {"task_id": "task-1"}},
                ),
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    first = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "查看当前任务详情",
            "page_context": _page_context(pathname="/tasks/task-1", task_id="task-1"),
        },
    )
    second = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "不用了",
            "page_context": _page_context(pathname="/tasks/task-1", task_id="task-1"),
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert call_count["value"] == 1
    assert second.json()["messages"][-1]["message_type"] == "text"
    assert "已取消上一轮补问" in second.json()["messages"][-1]["content"]


def test_admin_message_can_enter_waiting_approval(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="建议先为该主机安装 Runner，然后创建修复会话。",
                conversation_state="plan",
                read_tool_calls=[],
                proposed_write_actions=[
                    haor_agent_service._ProposedWriteAction(
                        action_type="install_runner",
                        title="安装 Host Runner",
                        reason="当前资产具备 SSH 管理员权限，适合切换到 Runner 执行模式。",
                        params={"asset_id": "asset-1"},
                    )
                ],
                needs_confirmation=True,
            ),
            [{"tool_name": "get_remediation_asset", "ok": True, "result": {"asset_id": "asset-1"}}],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "帮我处理这台主机",
            "page_context": _page_context(pathname="/remediation/asset-1", asset_id="asset-1"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "waiting_approval"
    assert body["working_context_json"]["asset_id"] == "asset-1"
    assert body["messages"][-1]["message_type"] == "plan"
    assert body["pending_plan_json"]["proposed_write_actions"][0]["action_type"] == "install_runner"


def test_post_haor_message_can_drive_ui_step_roundtrip(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")
    call_count = {"value": 0}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        browser_runtime = kwargs.get("browser_runtime") or {}
        completed_actions = browser_runtime.get("completed_ui_actions") or []
        if completed_actions:
            return (
                haor_agent_service._AgentModelDecision(
                    reply_markdown="已打开当前任务详情并完成分析。",
                    conversation_state="answer",
                ),
                [{"tool_name": "get_task_detail", "ok": True, "result": {"task_id": "task-1"}}],
            )
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="我先打开当前任务详情，再继续分析。",
                conversation_state="answer",
                ui_actions=[
                    haor_agent_service._UIAction(
                        action_type="click",
                        target_node_id="haor-node-task-1",
                        label_contains="任务详情",
                    )
                ],
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    first = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "查看这个任务详情",
            "page_context": _page_context(pathname="/tasks/task-1", task_id="task-1"),
            "browser_context": _browser_context(pathname="/tasks/task-1", task_id="task-1"),
        },
    )

    assert first.status_code == 200
    first_body = first.json()
    assert first_body["messages"][-1]["message_type"] == "action_update"
    assert first_body["browser_runtime_json"]["pending_ui_actions"][0]["action_type"] == "click"

    second = client.post(
        "/api/v1/agent/haor/session/steps",
        json={
            "step_request_id": "step-http-1",
            "browser_context": _browser_context(pathname="/tasks/task-1", task_id="task-1"),
            "ui_action_results": [
                {
                    "action_id": first_body["browser_runtime_json"]["pending_ui_actions"][0]["action_id"],
                    "action_type": "click",
                    "ok": True,
                    "target_node_id": "haor-node-task-1",
                    "resolved_node_id": "haor-node-task-1",
                    "message": "已打开任务详情",
                    "detail_json": {},
                }
            ],
        },
    )

    assert second.status_code == 200
    second_body = second.json()
    assert call_count["value"] == 2
    assert second_body["messages"][-1]["message_type"] == "text"
    assert "已打开当前任务详情并完成分析" in second_body["messages"][-1]["content"]
    assert second_body["browser_runtime_json"]["pending_ui_actions"] == []
    assert second_body["browser_runtime_json"]["last_step_request_id"] == "step-http-1"


def test_admin_message_can_auto_execute_safe_action(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")
    asset_id = f"asset-{uuid4().hex[:8]}"
    task_id = f"task-{uuid4().hex[:8]}"
    asset_ip = f"192.168.{int(uuid4().hex[:2], 16) % 200}.{int(uuid4().hex[2:4], 16) % 200 + 1}"

    with SessionLocal() as db:
        db.add(Asset(id=asset_id, ip=asset_ip, hostname=asset_id, status=AssetStatus.ONLINE))
        db.add(
            TaskRun(
                id=task_id,
                task_type=TaskType.RISK_VERIFY,
                status=TaskExecutionStatus.PENDING,
                scope_type="asset",
                scope_id=asset_id,
                progress=0,
                message="queued",
            )
        )
        db.commit()

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="我已直接为当前资产触发一次风险验证，并继续等待任务结果。",
                conversation_state="answer",
                auto_execute_actions=[
                    haor_agent_service._ProposedWriteAction(
                        action_type="verify_asset_risks",
                        title="触发资产风险验证",
                        reason="用户明确要求立即重新验证当前资产风险。",
                        params={"asset_id": asset_id},
                    )
                ],
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)
    monkeypatch.setattr(
        haor_agent_service,
        "execute_approved_action",
        lambda *args, **kwargs: haor_agent_service.AgentExecutionResult(
            status="queued",
            summary=f"已触发资产 {asset_id} 的风险验证",
            child_task_id=task_id,
            payload={"asset_id": asset_id},
        ),
    )

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": f"立即验证资产 {asset_id} 的风险",
            "page_context": _page_context(pathname=f"/assets/{asset_id}", asset_id=asset_id),
            "browser_context": _browser_context(pathname=f"/assets/{asset_id}", asset_id=asset_id),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["last_task_id"] == task_id
    assert any(item["message_type"] == "action_update" for item in body["messages"])
    assert body["messages"][-1]["message_type"] == "text"
    assert "风险验证" in body["messages"][-1]["payload_json"]["auto_executed_actions"][0]["summary"]


def test_post_haor_message_surfaces_upstream_5xx_detail(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        request = httpx.Request("POST", "https://example.test/v1/responses")
        response = httpx.Response(
            500,
            request=request,
            json={"error": {"message": "上游 JSON 输出不合法，缺少 output 字段"}},
        )
        raise httpx.HTTPStatusError("server error", request=request, response=response)

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "分析当前页面",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["messages"][-1]["message_type"] == "error"
    assert "上游 JSON 输出不合法" in body["messages"][-1]["content"]


def test_post_haor_message_summarizes_html_502_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        request = httpx.Request("POST", "https://risingsun.top/v1/responses")
        response = httpx.Response(
            502,
            request=request,
            headers={"content-type": "text/html; charset=UTF-8"},
            text="""
<!DOCTYPE html>
<html lang="en-US">
<head><title>risingsun.top | 502: Bad gateway</title></head>
<body><h1>Bad gateway</h1><p>Cloudflare</p></body>
</html>
            """.strip(),
        )
        raise httpx.HTTPStatusError("bad gateway", request=request, response=response)

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "分析当前页面",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert "Cloudflare 错误页" in body["messages"][-1]["content"]
    assert "502: Bad gateway" in body["messages"][-1]["content"]


def test_step_haor_session_returns_409_when_no_active_session(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    response = client.post(
        "/api/v1/agent/haor/session/steps",
        json={
            "browser_context": _browser_context(pathname="/tasks/task-1", task_id="task-1"),
            "ui_action_results": [],
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "当前没有可继续的 haor 会话"


def test_post_haor_message_maps_known_agent_upstream_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()

    def _raise_upstream(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise haor_agent_service.AgentUpstreamError("当前 AI 调用失败：上游模型网关当前不可用", stage="message")

    monkeypatch.setattr(agent_endpoint, "post_agent_message", _raise_upstream)

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "分析当前页面",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )

    assert response.status_code == 502
    assert response.json()["detail"] == "当前 AI 调用失败：上游模型网关当前不可用"


def test_post_haor_message_keeps_unknown_error_generic(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()

    def _raise_unknown(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise KeyError("unexpected")

    monkeypatch.setattr(agent_endpoint, "post_agent_message", _raise_unknown)

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "分析当前页面",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "后端服务异常，请稍后重试"


def test_analyst_cannot_approve_haor_plan(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client(role=UserRole.ANALYST)
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    with SessionLocal() as db:
        session = AgentSession(
            user_id=user_id,
            agent_id="haor",
            status="waiting_approval",
            pending_plan_json={
                "reply_markdown": "待执行",
                "proposed_write_actions": [
                    {
                        "action_type": "verify_asset_risks",
                        "title": "触发风险验证",
                        "reason": "需要重新校验当前资产风险状态",
                        "params": {"asset_id": "asset-1"},
                    }
                ],
            },
        )
        db.add(session)
        db.commit()

    response = client.post("/api/v1/agent/haor/session/approve", json={})

    assert response.status_code == 403


def test_approve_haor_plan_returns_409_when_pending_plan_missing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    with SessionLocal() as db:
        db.add(AgentSession(user_id=user_id, agent_id="haor", status="active", pending_plan_json={}))
        db.commit()

    response = client.post("/api/v1/agent/haor/session/approve", json={})

    assert response.status_code == 409
    assert response.json()["detail"] == "当前没有待批准的智能体动作计划"


def test_approve_haor_plan_creates_agent_orchestrate_task(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    with SessionLocal() as db:
        session = AgentSession(
            user_id=user_id,
            agent_id="haor",
            status="waiting_approval",
            pending_plan_json={
                "reply_markdown": "待执行",
                "page_context": {"pathname": "/assets/asset-1"},
                "working_context": {"asset_id": "asset-1", "summary": "资产 asset-1", "source": "page_reference"},
                "proposed_write_actions": [
                    {
                        "action_type": "verify_asset_risks",
                        "title": "触发风险验证",
                        "reason": "需要重新校验当前资产风险状态",
                        "params": {"asset_id": "asset-1"},
                    }
                ],
            },
        )
        db.add(session)
        db.commit()

    class _FakeDelayResult:
        id = "celery-agent-task-1"

    monkeypatch.setattr(
        "app.api.v1.endpoints.agent.run_agent_orchestrate_task.delay",
        lambda *args, **kwargs: _FakeDelayResult(),
    )

    response = client.post("/api/v1/agent/haor/session/approve", json={"note": "执行当前计划"})

    assert response.status_code == 202
    task_id = response.json()["task_id"]
    with SessionLocal() as db:
        task = db.get(TaskRun, task_id)
        assert task is not None
        assert task.task_type == TaskType.AGENT_ORCHESTRATE
        assert task.celery_task_id == "celery-agent-task-1"


def test_get_haor_session_reconciles_stale_running_agent_task(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    with SessionLocal() as db:
        session = AgentSession(
            user_id=user_id,
            agent_id="haor",
            status="running",
            pending_plan_json={"reply_markdown": "待执行"},
            dialog_state_json={"status": "awaiting_user_input"},
            browser_runtime_json={"phase": "awaiting_ui_feedback"},
            working_context_json={"asset_id": "asset-1", "summary": "资产 asset-1", "source": "session"},
        )
        db.add(session)
        db.flush()
        task = TaskRun(
            task_type=TaskType.AGENT_ORCHESTRATE,
            status=TaskExecutionStatus.CANCELED,
            scope_type="agent_session",
            scope_id=session.id,
            message="任务已中断",
        )
        db.add(task)
        db.flush()
        session.last_task_id = task.id
        db.add(session)
        db.commit()

    response = client.get("/api/v1/agent/haor/session")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["last_task_id"] == task.id
    assert body["pending_plan_json"] == {}
    assert body["dialog_state_json"] == {}
    assert body["browser_runtime_json"]["phase"] == "idle"
    assert body["working_context_json"]["asset_id"] == "asset-1"
    assert body["messages"][-1]["payload_json"]["interrupted"] is True


def test_post_haor_message_returns_409_when_agent_orchestrate_task_is_running(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    with SessionLocal() as db:
        session = AgentSession(user_id=user_id, agent_id="haor", status="running")
        db.add(session)
        db.flush()
        task = TaskRun(
            task_type=TaskType.AGENT_ORCHESTRATE,
            status=TaskExecutionStatus.RUNNING,
            scope_type="agent_session",
            scope_id=session.id,
            celery_task_id="celery-agent-task-1",
            message="执行中",
        )
        db.add(task)
        db.flush()
        session.last_task_id = task.id
        db.add(session)
        db.commit()

    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "继续分析当前对象",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "当前 haor 正在执行编排任务，请先中断当前任务"


def test_reset_haor_session_interrupts_running_task_and_creates_new_session(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    revoked: dict[str, object] = {}

    def _fake_revoke(task_id: str, *, terminate: bool, signal: str) -> None:
        revoked.update({"task_id": task_id, "terminate": terminate, "signal": signal})

    monkeypatch.setattr(haor_agent_service.celery_app.control, "revoke", _fake_revoke)

    with SessionLocal() as db:
        session = AgentSession(user_id=user_id, agent_id="haor", status="running")
        db.add(session)
        db.flush()
        task = TaskRun(
            task_type=TaskType.AGENT_ORCHESTRATE,
            status=TaskExecutionStatus.RUNNING,
            scope_type="agent_session",
            scope_id=session.id,
            celery_task_id="celery-agent-task-1",
            message="执行中",
        )
        db.add(task)
        db.flush()
        session.last_task_id = task.id
        db.add(session)
        db.commit()

    response = client.post("/api/v1/agent/haor/session/reset", json={})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["messages"] == []
    assert body["session_id"] != session.id
    assert revoked == {"task_id": "celery-agent-task-1", "terminate": True, "signal": "SIGTERM"}

    with SessionLocal() as db:
        previous_session = db.get(AgentSession, session.id)
        previous_task = db.get(TaskRun, task.id)
        assert previous_session is not None
        assert previous_task is not None
        assert previous_session.status == "completed"
        assert previous_task.status == TaskExecutionStatus.CANCELED


def test_reset_haor_session_prevents_late_message_reply_from_old_turn(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    started = threading.Event()
    release = threading.Event()
    holder: dict[str, object] = {}

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        started.set()
        assert release.wait(timeout=5)
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="这条旧回复不应该再落回原会话。",
                conversation_state="answer",
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)

    def _send_first() -> None:
        holder["response"] = client.post(
            "/api/v1/agent/haor/session/messages",
            json={
                "client_message_id": "client-msg-reset-1",
                "content": "分析我当前页面上的对象",
                "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
                "browser_context": _browser_context(pathname="/assets/asset-1", asset_id="asset-1"),
            },
        )

    thread = threading.Thread(target=_send_first)
    thread.start()
    assert started.wait(timeout=5)

    with SessionLocal() as db:
        old_session = db.query(AgentSession).filter(AgentSession.user_id == user_id).order_by(AgentSession.created_at.desc()).first()
        assert old_session is not None
        old_session_id = old_session.id

    reset = client.post("/api/v1/agent/haor/session/reset", json={})
    release.set()
    thread.join(timeout=5)

    assert reset.status_code == 200
    first = holder["response"]
    assert isinstance(first, httpx.Response)
    assert first.status_code == 200

    with SessionLocal() as db:
        previous_session = db.get(AgentSession, old_session_id)
        latest_session = db.query(AgentSession).filter(AgentSession.user_id == user_id).order_by(AgentSession.created_at.desc()).first()
        assert previous_session is not None
        assert latest_session is not None
        assert previous_session.status == "completed"
        assert latest_session.id != old_session_id
        assistant_messages = [item for item in previous_session.messages if item.role == "assistant"]
        assert assistant_messages == []
        user_messages = [item for item in previous_session.messages if item.role == "user"]
        assert len(user_messages) == 1


def test_interrupt_haor_session_cancels_task_and_restores_input_state(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    revoked: dict[str, object] = {}

    def _fake_revoke(task_id: str, *, terminate: bool, signal: str) -> None:
        revoked.update({"task_id": task_id, "terminate": terminate, "signal": signal})

    monkeypatch.setattr(haor_agent_service.celery_app.control, "revoke", _fake_revoke)

    with SessionLocal() as db:
        session = AgentSession(
            user_id=user_id,
            agent_id="haor",
            status="running",
            dialog_state_json={"status": "awaiting_user_input"},
            browser_runtime_json={"phase": "awaiting_ui_feedback"},
            working_context_json={"asset_id": "asset-1", "summary": "资产 asset-1", "source": "session"},
        )
        db.add(session)
        db.flush()
        task = TaskRun(
            task_type=TaskType.AGENT_ORCHESTRATE,
            status=TaskExecutionStatus.RUNNING,
            scope_type="agent_session",
            scope_id=session.id,
            celery_task_id="celery-agent-task-1",
            message="执行中",
        )
        db.add(task)
        db.flush()
        session.last_task_id = task.id
        db.add(session)
        db.commit()

    response = client.post("/api/v1/agent/haor/session/interrupt", json={})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["last_task_id"] == task.id
    assert body["pending_plan_json"] == {}
    assert body["dialog_state_json"] == {}
    assert body["browser_runtime_json"]["phase"] == "idle"
    assert body["working_context_json"]["asset_id"] == "asset-1"
    assert body["messages"][-1]["message_type"] == "task_update"
    assert body["messages"][-1]["payload_json"]["interrupted"] is True
    assert revoked == {"task_id": "celery-agent-task-1", "terminate": True, "signal": "SIGTERM"}

    with SessionLocal() as db:
        saved_session = db.get(AgentSession, body["session_id"])
        saved_task = db.get(TaskRun, task.id)
        assert saved_session is not None
        assert saved_task is not None
        assert saved_session.status == "active"
        assert saved_session.working_context_json["asset_id"] == "asset-1"
        assert saved_task.status == TaskExecutionStatus.CANCELED


def test_interrupt_haor_session_returns_409_when_no_running_task(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    with SessionLocal() as db:
        db.add(AgentSession(user_id=user_id, agent_id="haor", status="active"))
        db.commit()

    response = client.post("/api/v1/agent/haor/session/interrupt", json={})

    assert response.status_code == 409
    assert response.json()["detail"] == "当前没有运行中的 haor 编排任务"


def test_soft_focus_is_not_rebound_by_page_change_without_reference(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    first = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "分析我当前页面上的对象",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )
    second = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "继续分析",
            "page_context": _page_context(pathname="/assets/asset-2", asset_id="asset-2"),
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200
    body = second.json()
    assert body["working_context_json"]["asset_id"] == "asset-1"
    assert "资产 asset-1" in body["messages"][-1]["content"]


def test_soft_focus_allows_switching_target_in_same_session(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, _ = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")

    client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "分析我当前页面上的对象",
            "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
        },
    )
    response = client.post(
        "/api/v1/agent/haor/session/messages",
        json={
            "content": "帮我处理资产 asset-2",
            "page_context": _page_context(pathname="/assets/asset-2", asset_id="asset-2"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["messages"][-1]["message_type"] == "text"
    assert body["working_context_json"]["asset_id"] == "asset-2"


def test_haor_websocket_stream_sends_initial_snapshot(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    token = _build_ws_token(user_id, UserRole.ADMIN)

    with client.websocket_connect(f"/api/v1/agent/haor/session/stream?token={token}") as websocket:
        payload = websocket.receive_json()

    assert payload["type"] == "session_snapshot"
    assert payload["session"]["agent_id"] == "haor"


def test_haor_websocket_hello_refreshes_snapshot_without_starting_turn(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    token = _build_ws_token(user_id, UserRole.ADMIN)

    with client.websocket_connect(f"/api/v1/agent/haor/session/stream?token={token}") as websocket:
        initial = websocket.receive_json()
        websocket.send_json(
            {
                "type": "hello",
                "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
                "browser_context": _browser_context(pathname="/assets/asset-1", asset_id="asset-1"),
            }
        )
        refreshed = websocket.receive_json()

    assert initial["type"] == "session_snapshot"
    assert refreshed["type"] == "session_snapshot"
    assert refreshed["session"]["session_id"] == initial["session"]["session_id"]


def test_haor_websocket_stream_message_turn_emits_deltas(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    token = _build_ws_token(user_id, UserRole.ADMIN)

    with client.websocket_connect(f"/api/v1/agent/haor/session/stream?token={token}") as websocket:
        websocket.receive_json()
        websocket.send_json(
            {
                "type": "message",
                "client_message_id": "client-msg-1",
                "content": "分析我当前页面上的对象",
                "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
                "browser_context": _browser_context(pathname="/assets/asset-1", asset_id="asset-1"),
            }
        )
        events = _receive_ws_events_until(websocket, stop_type="turn_done")

    event_types = [item["type"] for item in events]
    assert "turn_started" in event_types
    assert "assistant_message_start" in event_types
    assert "assistant_message_delta" in event_types
    assert "assistant_message_done" in event_types
    assert "turn_done" in event_types
    done_event = next(item for item in events if item["type"] == "assistant_message_done")
    assert done_event["message"]["message_type"] == "text"


def test_haor_websocket_stream_message_turn_uses_provider_stream_reply(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="这是同步草稿，不应该直接按切块回放。",
                conversation_state="answer",
            ),
            [],
        )

    class _FakeProvider:
        def stream_generate(self, request):  # type: ignore[no-untyped-def]
            yield "原生"
            yield "流式"
            yield "回复"

        def generate(self, request):  # type: ignore[no-untyped-def]
            return "原生流式回复"

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)
    monkeypatch.setattr(
        haor_agent_service,
        "_build_runtime_provider",
        lambda: SimpleNamespace(provider=_FakeProvider()),
    )
    token = _build_ws_token(user_id, UserRole.ADMIN)

    with client.websocket_connect(f"/api/v1/agent/haor/session/stream?token={token}") as websocket:
        websocket.receive_json()
        websocket.send_json(
            {
                "type": "message",
                "client_message_id": "client-msg-2",
                "content": "告诉我当前分析结果",
                "page_context": _page_context(pathname="/assets/asset-1", asset_id="asset-1"),
                "browser_context": _browser_context(pathname="/assets/asset-1", asset_id="asset-1"),
            }
        )
        events = _receive_ws_events_until(websocket, stop_type="turn_done")

    deltas = [item["delta"] for item in events if item["type"] == "assistant_message_delta"]
    done_event = next(item for item in events if item["type"] == "assistant_message_done")
    assert deltas == ["原生", "流式", "回复"]
    assert done_event["message"]["content"] == "原生流式回复"


def test_haor_websocket_ui_step_continues_turn_flow(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "openai_compatible")
    call_count = {"value": 0}
    step_request_id = "step-ws-1"

    class _FakeProvider:
        def stream_generate(self, request):  # type: ignore[no-untyped-def]
            yield "已在站内"
            yield "完成详情打开，并继续给出分析结果。"

        def generate(self, request):  # type: ignore[no-untyped-def]
            return "已在站内完成详情打开，并继续给出分析结果。"

    def _fake_run_loop(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["value"] += 1
        browser_runtime = kwargs.get("browser_runtime") or {}
        completed_actions = browser_runtime.get("completed_ui_actions") or []
        if completed_actions:
            return (
                haor_agent_service._AgentModelDecision(
                    reply_markdown="已在站内完成详情打开，并继续给出分析结果。",
                    conversation_state="answer",
                ),
                [{"tool_name": "get_task_detail", "ok": True, "result": {"task_id": "task-1"}}],
            )
        return (
            haor_agent_service._AgentModelDecision(
                reply_markdown="我先打开当前任务详情。",
                conversation_state="answer",
                ui_actions=[
                    haor_agent_service._UIAction(
                        action_type="click",
                        target_node_id="haor-node-task-1",
                        label_contains="任务详情",
                    )
                ],
            ),
            [],
        )

    monkeypatch.setattr(haor_agent_service, "_run_agent_loop", _fake_run_loop)
    monkeypatch.setattr(
        haor_agent_service,
        "_build_runtime_provider",
        lambda: SimpleNamespace(provider=_FakeProvider()),
    )
    token = _build_ws_token(user_id, UserRole.ADMIN)

    with client.websocket_connect(f"/api/v1/agent/haor/session/stream?token={token}") as websocket:
        websocket.receive_json()
        websocket.send_json(
            {
                "type": "message",
                "client_message_id": "client-msg-ui-step",
                "content": "打开这个任务详情并继续分析",
                "page_context": _page_context(pathname="/tasks/task-1", task_id="task-1"),
                "browser_context": _browser_context(pathname="/tasks/task-1", task_id="task-1"),
            }
        )
        first_events = _receive_ws_events_until(websocket, stop_type="turn_done")
        ui_request = next(item for item in first_events if item["type"] == "ui_actions_requested")
        action_id = ui_request["ui_actions"][0]["action_id"]

        websocket.send_json(
            {
                "type": "ui_step",
                "step_request_id": step_request_id,
                "browser_context": _browser_context(pathname="/tasks/task-1", task_id="task-1"),
                "ui_action_results": [
                    {
                        "action_id": action_id,
                        "action_type": "click",
                        "ok": True,
                        "target_node_id": "haor-node-task-1",
                        "resolved_node_id": "haor-node-task-1",
                        "message": "已打开任务详情",
                        "detail_json": {},
                    }
                ],
            }
        )
        second_events = _receive_ws_events_until(websocket, stop_type="turn_done")

    duplicate = client.post(
        "/api/v1/agent/haor/session/steps",
        json={
            "step_request_id": step_request_id,
            "browser_context": _browser_context(pathname="/tasks/task-1", task_id="task-1"),
            "ui_action_results": [
                {
                    "action_id": action_id,
                    "action_type": "click",
                    "ok": True,
                    "target_node_id": "haor-node-task-1",
                    "resolved_node_id": "haor-node-task-1",
                    "message": "已打开任务详情",
                    "detail_json": {},
                }
            ],
        },
    )

    first_event_types = [item["type"] for item in first_events]
    second_event_types = [item["type"] for item in second_events]
    assert "action_update" in first_event_types
    assert "ui_actions_requested" in first_event_types
    assert second_events[0]["type"] == "turn_started"
    assert second_events[0]["phase"] == "ui_step"
    assert "assistant_message_start" in second_event_types
    assert "assistant_message_done" in second_event_types
    assert second_event_types.count("turn_done") == 1
    done_event = next(item for item in second_events if item["type"] == "assistant_message_done")
    assert done_event["message"]["content"] == "已在站内完成详情打开，并继续给出分析结果。"
    assert duplicate.status_code == 200
    assert duplicate.json()["browser_runtime_json"]["last_step_request_id"] == step_request_id
    assert call_count["value"] == 2


def test_haor_websocket_approve_plan_emits_task_update_and_snapshot(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, user_id = _build_client()
    monkeypatch.setattr(haor_agent_service.settings, "LLM_PROVIDER", "mock")
    monkeypatch.setattr(
        agent_endpoint.run_agent_orchestrate_task,
        "delay",
        lambda task_id, session_id: SimpleNamespace(id="celery-agent-task-1"),
    )
    token = _build_ws_token(user_id, UserRole.ADMIN)

    with SessionLocal() as db:
        session = AgentSession(
            user_id=user_id,
            agent_id="haor",
            status="waiting_approval",
            pending_plan_json={
                "reply_markdown": "待确认计划",
                "proposed_write_actions": [
                    {
                        "action_type": "verify_asset_risks",
                        "title": "验证当前资产风险",
                        "reason": "需要重新校验",
                        "params": {"asset_id": "asset-1"},
                    }
                ],
                "working_context": {"asset_id": "asset-1"},
            },
            working_context_json={"asset_id": "asset-1"},
        )
        db.add(session)
        db.commit()

    with client.websocket_connect(f"/api/v1/agent/haor/session/stream?token={token}") as websocket:
        websocket.receive_json()
        websocket.send_json({"type": "approve_plan"})
        events = _receive_ws_events_until(websocket, stop_type="turn_done")

    event_types = [item["type"] for item in events]
    assert "turn_started" in event_types
    assert "task_update" in event_types
    assert "session_snapshot" in event_types
    snapshot = next(item for item in reversed(events) if item["type"] == "session_snapshot")
    assert snapshot["session"]["status"] == "running"
    assert snapshot["session"]["last_task_id"]
