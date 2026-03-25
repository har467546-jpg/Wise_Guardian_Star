from __future__ import annotations

from types import SimpleNamespace

from app.tasks import agent_tasks


class _FakeDB:
    def __init__(self, session):
        self._session = session
        self.committed = False

    def get(self, _model, value):
        if value == getattr(self._session, "id", None):
            return self._session
        return None

    def commit(self) -> None:
        self.committed = True


class _SessionLocalContext:
    def __init__(self, db):
        self._db = db

    def __call__(self):
        return self

    def __enter__(self):
        return self._db

    def __exit__(self, exc_type, exc, tb):
        return False


def test_run_agent_auto_followup_task_appends_completion_message(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(id="session-1", messages=[])
    db = _FakeDB(session)
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": "success",
            "message": "扫描任务完成",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))

    def _fake_append(db_obj, *, session_id, content, payload_json=None, message_type="task_update"):  # type: ignore[no-untyped-def]
        captured["db"] = db_obj
        captured["session_id"] = session_id
        captured["content"] = content
        captured["payload_json"] = payload_json
        captured["message_type"] = message_type

    monkeypatch.setattr(agent_tasks, "append_agent_task_message", _fake_append)

    result = agent_tasks.run_agent_auto_followup_task.run(
        "session-1",
        "task-child-1",
        {"action_type": "create_discovery_job", "params": {"cidr": "192.168.10.0/24"}},
    )

    assert result == "task-child-1"
    assert db.committed is True
    assert captured["db"] is db
    assert captured["session_id"] == "session-1"
    assert captured["message_type"] == "task_update"
    assert "192.168.10.0/24 的扫描任务已完成" in str(captured["content"])
    payload_json = captured["payload_json"]
    assert isinstance(payload_json, dict)
    assert payload_json["auto_followup"] is True
    assert payload_json["task_id"] == "task-child-1"
    assert payload_json["resume_hint"]["kind"] == "post_scan_analysis"
    assert payload_json["resume_hint"]["preferred_read_tools"][0]["tool_name"] == "list_assets"


def test_run_agent_auto_followup_task_skips_duplicate_followup_messages(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(
        id="session-1",
        messages=[SimpleNamespace(payload_json={"task_id": "task-child-1", "auto_followup": True})],
    )
    db = _FakeDB(session)

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": "success",
            "message": "扫描任务完成",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(
        agent_tasks,
        "append_agent_task_message",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not append duplicate follow-up")),
    )

    result = agent_tasks.run_agent_auto_followup_task.run(
        "session-1",
        "task-child-1",
        {"action_type": "create_discovery_job", "params": {"cidr": "192.168.10.0/24"}},
    )

    assert result == "task-child-1"
    assert db.committed is False


def test_run_agent_auto_followup_task_formats_remediation_completion(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(id="session-1", messages=[])
    db = _FakeDB(session)
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": "success",
            "message": "Runner 已完成整机修复",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))

    def _fake_append(db_obj, *, session_id, content, payload_json=None, message_type="task_update"):  # type: ignore[no-untyped-def]
        captured["db"] = db_obj
        captured["session_id"] = session_id
        captured["content"] = content
        captured["payload_json"] = payload_json
        captured["message_type"] = message_type

    monkeypatch.setattr(agent_tasks, "append_agent_task_message", _fake_append)

    result = agent_tasks.run_agent_auto_followup_task.run(
        "session-1",
        "task-remediation-1",
        {
            "action_type": "create_or_resume_remediation_session",
            "params": {"asset_id": "asset-9", "submit_if_ready": True},
            "payload": {"session_id": "session-9"},
        },
    )

    assert result == "task-remediation-1"
    assert db.committed is True
    assert captured["message_type"] == "task_update"
    assert "资产 asset-9 的自动修复任务已完成" in str(captured["content"])
    assert "修复会话 session-9" in str(captured["content"])
    payload_json = captured["payload_json"]
    assert isinstance(payload_json, dict)
    assert payload_json["resume_hint"]["kind"] == "post_remediation_review"
    preferred_read_tools = payload_json["resume_hint"]["preferred_read_tools"]
    assert any(item["tool_name"] == "get_remediation_session" for item in preferred_read_tools)
