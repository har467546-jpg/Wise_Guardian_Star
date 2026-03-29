from types import SimpleNamespace

from app.services.agent import execution_registry


class _UserLookupDB:
    def __init__(self, valid_user_ids: set[str] | None = None):
        self._valid_user_ids = valid_user_ids or set()

    def get(self, model, value):
        if model is execution_registry.User and value in self._valid_user_ids:
            return SimpleNamespace(id=value)
        return None


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
    observed: dict[str, str] = {}

    monkeypatch.setattr(
        execution_registry,
        "create_or_resume_remediation_session",
        lambda db, asset_id: SimpleNamespace(
            session_id="session-1",
            plan=SimpleNamespace(execution_ready=True, blocked_reasons=[]),
        ),
    )

    def _approve_remediation_session(db, session_id, approved_by, **kwargs):  # type: ignore[no-untyped-def]
        observed["approved_by"] = approved_by
        return SimpleNamespace(task_id="remediation-task-1")

    monkeypatch.setattr(execution_registry, "approve_remediation_session", _approve_remediation_session)

    context = execution_registry.AgentActionExecutorContext(
        db=_UserLookupDB({"user-1"}),
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
        "blocker_codes": [],
        "blocker_categories": [],
        "blockers": [],
        "submitted_task_id": "remediation-task-1",
        "stage_code": None,
        "execution_mode": "apply",
        "change_ticket": None,
        "maintenance_window_id": None,
    }
    assert observed["approved_by"] == "user-1"
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
        db=_UserLookupDB({"user-1"}),
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
        "blocker_codes": ["runner_not_installed"],
        "blocker_categories": ["runner"],
        "blockers": [
            {
                "code": "runner_not_installed",
                "message": "当前主机尚未安装 Host Runner",
                "blocker_category": "runner",
                "scope": None,
                "blocking": None,
                "stage_code": None,
                "step_id": None,
            }
        ],
        "submitted_task_id": None,
    }
    assert "当前未自动执行" in result.summary
    assert "当前主机尚未安装 Host Runner" in result.summary


def test_create_or_resume_remediation_prefers_structured_plan_blockers(monkeypatch) -> None:
    monkeypatch.setattr(
        execution_registry,
        "create_or_resume_remediation_session",
        lambda db, asset_id: SimpleNamespace(
            session_id="session-structured-1",
            plan=SimpleNamespace(
                execution_ready=False,
                blocked_reasons=["当前自动修复仍缺少 SSH 管理员凭据"],
                global_blockers=[
                    {
                        "code": "unknown_blocker",
                        "message": "当前自动修复仍缺少 SSH 管理员凭据",
                        "scope": "asset",
                        "blocking": "hard",
                        "stage_code": "preflight",
                    }
                ],
                step_blockers=[
                    {
                        "code": "runner_not_installed",
                        "message": "当前主机尚未安装 Host Runner",
                        "scope": "asset",
                        "blocking": "hard",
                        "step_id": "install-runner",
                    }
                ],
            ),
        ),
    )
    monkeypatch.setattr(
        execution_registry,
        "approve_remediation_session",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not submit remediation")),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=_UserLookupDB({"user-1"}),
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

    assert result.payload["blocker_codes"] == ["missing_ssh_credential", "runner_not_installed"]
    assert result.payload["blocker_categories"] == ["ssh", "runner"]
    assert result.payload["blockers"] == [
        {
            "code": "missing_ssh_credential",
            "message": "当前自动修复仍缺少 SSH 管理员凭据",
            "blocker_category": "ssh",
            "scope": "asset",
            "blocking": "hard",
            "stage_code": "preflight",
            "step_id": None,
        },
        {
            "code": "runner_not_installed",
            "message": "当前主机尚未安装 Host Runner",
            "blocker_category": "runner",
            "scope": "asset",
            "blocking": "hard",
            "stage_code": None,
            "step_id": "install-runner",
        },
    ]


def test_create_or_resume_remediation_marks_render_blockers(monkeypatch) -> None:
    monkeypatch.setattr(
        execution_registry,
        "create_or_resume_remediation_session",
        lambda db, asset_id: SimpleNamespace(
            session_id="session-render-1",
            plan=SimpleNamespace(
                execution_ready=False,
                blocked_reasons=["未识别到稳定的软件包管理器或包名"],
            ),
        ),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=_UserLookupDB({"user-1"}),
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

    assert result.payload["blocker_codes"] == ["unstable_render"]
    assert result.payload["blocker_categories"] == ["render"]
    assert result.payload["blockers"] == [
        {
            "code": "unstable_render",
            "message": "未识别到稳定的软件包管理器或包名",
            "blocker_category": "render",
            "scope": None,
            "blocking": None,
            "stage_code": None,
            "step_id": None,
        }
    ]


def test_approve_remediation_uses_session_user_id(monkeypatch) -> None:
    observed: dict[str, str] = {}

    def _approve_remediation_session(db, session_id, approved_by, **kwargs):  # type: ignore[no-untyped-def]
        observed["session_id"] = session_id
        observed["approved_by"] = approved_by
        return SimpleNamespace(task_id="remediation-task-9")

    monkeypatch.setattr(execution_registry, "approve_remediation_session", _approve_remediation_session)

    context = execution_registry.AgentActionExecutorContext(
        db=_UserLookupDB({"user-9"}),
        session_user_id="user-9",
        platform_url="http://localhost:3000",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    result = execution_registry.execute_registered_action(
        context,
        action={"action_type": "approve_remediation_session", "params": {"session_id": "session-9"}},
    )

    assert result.status == "queued"
    assert result.child_task_id == "remediation-task-9"
    assert observed == {"session_id": "session-9", "approved_by": "user-9"}


def test_approve_remediation_returns_blocked_result_when_maintenance_window_required(monkeypatch) -> None:
    class _RemediationLookupDB(_UserLookupDB):
        def get(self, model, value):
            if model is execution_registry.RemediationSession and value == "session-9":
                return SimpleNamespace(id="session-9", asset_id="asset-1")
            return super().get(model, value)

    monkeypatch.setattr(
        execution_registry,
        "approve_remediation_session",
        lambda db, session_id, approved_by, **kwargs: (_ for _ in ()).throw(
            RuntimeError("当前阶段包含高风险步骤，请先填写 maintenance_window_id 后再正式执行")
        ),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=_RemediationLookupDB({"user-9"}),
        session_user_id="user-9",
        platform_url="http://localhost:3000",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    result = execution_registry.execute_registered_action(
        context,
        action={"action_type": "approve_remediation_session", "params": {"session_id": "session-9"}},
    )

    assert result.status == "success"
    assert result.child_task_id is None
    assert "maintenance_window_id" in result.summary
    assert result.payload["asset_id"] == "asset-1"
    assert result.payload["blocker_codes"] == ["maintenance_window_required"]
    assert result.payload["blocker_categories"] == ["policy"]


def test_create_or_resume_remediation_auto_submit_returns_blocked_result_when_maintenance_window_required(monkeypatch) -> None:
    monkeypatch.setattr(
        execution_registry,
        "create_or_resume_remediation_session",
        lambda db, asset_id: SimpleNamespace(
            session_id="session-10",
            plan=SimpleNamespace(
                execution_ready=True,
                blocked_reasons=[],
            ),
        ),
    )
    monkeypatch.setattr(
        execution_registry,
        "approve_remediation_session",
        lambda db, session_id, approved_by, **kwargs: (_ for _ in ()).throw(
            RuntimeError("当前阶段包含高风险步骤，请先填写 maintenance_window_id 后再正式执行")
        ),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=_UserLookupDB({"user-10"}),
        session_user_id="user-10",
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
    assert "maintenance_window_id" in result.summary
    assert result.payload["asset_id"] == "asset-1"
    assert result.payload["session_id"] == "session-10"
    assert result.payload["blocker_codes"] == ["maintenance_window_required"]
    assert result.payload["blocker_categories"] == ["policy"]


def test_create_or_resume_remediation_rejects_empty_session_user_id(monkeypatch) -> None:
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
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not submit remediation")),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=_UserLookupDB({"user-1"}),
        session_user_id="",
        platform_url="http://localhost:3000",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    try:
        execution_registry.execute_registered_action(
            context,
            action={
                "action_type": "create_or_resume_remediation_session",
                "params": {"asset_id": "asset-1", "submit_if_ready": True},
            },
        )
    except RuntimeError as exc:
        assert str(exc) == "审批人信息无效，请刷新页面后重试"
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("expected RuntimeError for missing session user id")


def test_approve_remediation_rejects_unknown_session_user_id(monkeypatch) -> None:
    monkeypatch.setattr(
        execution_registry,
        "approve_remediation_session",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not submit remediation")),
    )

    context = execution_registry.AgentActionExecutorContext(
        db=_UserLookupDB(),
        session_user_id="haor",
        platform_url="http://localhost:3000",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    try:
        execution_registry.execute_registered_action(
            context,
            action={"action_type": "approve_remediation_session", "params": {"session_id": "session-9"}},
        )
    except RuntimeError as exc:
        assert str(exc) == "审批人信息无效，请刷新页面后重试"
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("expected RuntimeError for invalid session user id")
