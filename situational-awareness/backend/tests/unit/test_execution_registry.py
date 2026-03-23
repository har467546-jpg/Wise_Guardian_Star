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
