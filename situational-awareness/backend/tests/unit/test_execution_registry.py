from types import SimpleNamespace

from app.services.agent import execution_registry


def test_queue_discovery_job_normalizes_host_bits(monkeypatch) -> None:
    observed: dict[str, str] = {}

    def _get_active_job_by_cidr(db, cidr):  # type: ignore[no-untyped-def]
        observed["lookup_cidr"] = cidr
        return None

    def _create_job(**kwargs):  # type: ignore[no-untyped-def]
        observed["create_cidr"] = kwargs["cidr"]
        return SimpleNamespace(id="job-1")

    monkeypatch.setattr(execution_registry, "get_active_job_by_cidr", _get_active_job_by_cidr)
    monkeypatch.setattr(execution_registry, "create_job", _create_job)
    monkeypatch.setattr(execution_registry, "get_latest_task_run_for_scope", lambda *args, **kwargs: None)
    monkeypatch.setattr(execution_registry, "create_task_run", lambda *args, **kwargs: SimpleNamespace(id="task-1"))
    monkeypatch.setattr(execution_registry, "update_task_run", lambda db, task_run, **kwargs: task_run)
    monkeypatch.setattr(
        execution_registry,
        "run_asset_scan_task",
        SimpleNamespace(delay=lambda *args, **kwargs: SimpleNamespace(id="celery-task-1")),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=SimpleNamespace(),
        session_user_id="user-1",
        platform_url="http://localhost:3000",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    result = execution_registry.execute_registered_action(
        context,
        action={"action_type": "create_discovery_job", "params": {"cidr": "192.168.10.1/24"}},
    )

    assert observed["lookup_cidr"] == "192.168.10.0/24"
    assert observed["create_cidr"] == "192.168.10.0/24"
    assert result.status == "queued"
    assert result.payload == {"job_id": "job-1", "task_id": "task-1", "reused": False}


def test_queue_discovery_job_rejects_invalid_cidr(monkeypatch) -> None:
    context = execution_registry.AgentActionExecutorContext(
        db=SimpleNamespace(),
        session_user_id="user-1",
        platform_url="http://localhost:3000",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    try:
        execution_registry.execute_registered_action(
            context,
            action={"action_type": "create_discovery_job", "params": {"cidr": "999.999.999.999/24"}},
        )
    except RuntimeError as exc:
        assert str(exc) == "扫描计划中的 CIDR 不合法：999.999.999.999/24"
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("expected RuntimeError for invalid CIDR")


def test_create_or_resume_remediation_auto_submits_when_ready(monkeypatch) -> None:
    monkeypatch.setattr(
        execution_registry,
        "create_or_resume_remediation_session",
        lambda db, asset_id: SimpleNamespace(
            session_id="session-1",
            plan=SimpleNamespace(execution_ready=True, blocked_reasons=[]),
        ),
    )
    monkeypatch.setattr(
        execution_registry,
        "approve_remediation_session",
        lambda db, session_id, approved_by: SimpleNamespace(task_id="remediation-task-1"),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=SimpleNamespace(),
        session_user_id="user-1",
        platform_url="http://localhost:3000",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    result = execution_registry.execute_registered_action(
        context,
        action={
            "action_type": "create_or_resume_remediation_session",
            "params": {"asset_id": "asset-1", "submit_if_ready": True},
        },
    )

    assert result.status == "queued"
    assert result.child_task_id == "remediation-task-1"
    assert result.payload == {
        "asset_id": "asset-1",
        "session_id": "session-1",
        "execution_ready": True,
        "blocked_reasons": [],
        "submitted_task_id": "remediation-task-1",
    }
    assert "直接提交自动修复任务 remediation-task-1" in result.summary


def test_create_or_resume_remediation_returns_blockers_without_submitting(monkeypatch) -> None:
    monkeypatch.setattr(
        execution_registry,
        "create_or_resume_remediation_session",
        lambda db, asset_id: SimpleNamespace(
            session_id="session-1",
            plan=SimpleNamespace(execution_ready=False, blocked_reasons=["当前主机尚未安装 Host Runner"]),
        ),
    )
    monkeypatch.setattr(
        execution_registry,
        "approve_remediation_session",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not submit remediation")),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=SimpleNamespace(),
        session_user_id="user-1",
        platform_url="http://localhost:3000",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    result = execution_registry.execute_registered_action(
        context,
        action={
            "action_type": "create_or_resume_remediation_session",
            "params": {"asset_id": "asset-1", "submit_if_ready": True},
        },
    )

    assert result.status == "success"
    assert result.child_task_id is None
    assert result.payload == {
        "asset_id": "asset-1",
        "session_id": "session-1",
        "execution_ready": False,
        "blocked_reasons": ["当前主机尚未安装 Host Runner"],
        "submitted_task_id": None,
    }
    assert "当前未自动执行" in result.summary
    assert "当前主机尚未安装 Host Runner" in result.summary
