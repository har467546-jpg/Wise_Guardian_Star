from types import SimpleNamespace

from app.db.models.enums import TaskExecutionStatus, TaskType
from app.services.remediation_business_service import BUSINESS_STATUS_PENDING_REVERIFY, BUSINESS_STATUS_VERIFIED_CLOSED
from app.schemas.remediation import HostRemediationPlanStepRead, RemediationBlockerRead
from app.services.remediation_session_service import _assign_host_plan_step_ids, _reconcile_session_task_progress


def test_assign_host_plan_step_ids_reindexes_duplicates_per_phase() -> None:
    steps = [
        HostRemediationPlanStepRead(
            step_id="step-1",
            action_type="toggle_feature",
            title="关闭 Apache 目录列表",
            phase_code="remove_exposure",
            phase_name="暴露面收敛",
            execution_state="ready",
            blockers=[],
        ),
        HostRemediationPlanStepRead(
            step_id="step-1",
            action_type="toggle_feature",
            title="关闭 SSH 密码登录",
            phase_code="remove_exposure",
            phase_name="暴露面收敛",
            execution_state="ready",
            blockers=[
                RemediationBlockerRead(
                    code="test",
                    message="需要人工确认",
                    scope="step",
                    blocking="soft",
                    stage_code="remove_exposure",
                    step_id="step-1",
                )
            ],
        ),
        HostRemediationPlanStepRead(
            step_id="step-1",
            action_type="restart_service",
            title="重载 SSH 服务",
            phase_code="service_control",
            phase_name="服务控制",
            execution_state="ready",
            blockers=[],
        ),
    ]

    step_blockers = _assign_host_plan_step_ids(steps)

    assert [item.step_id for item in steps] == [
        "remove_exposure-step-1",
        "remove_exposure-step-2",
        "service_control-step-1",
    ]
    assert steps[1].blockers[0].step_id == "remove_exposure-step-2"
    assert step_blockers[0].step_id == "remove_exposure-step-2"


class _FakeDB:
    def __init__(self, task) -> None:  # type: ignore[no-untyped-def]
        self.task = task
        self.added = []

    def get(self, model, task_id):  # type: ignore[no-untyped-def]
        return self.task if task_id == self.task.id else None

    def add(self, item) -> None:  # type: ignore[no-untyped-def]
        self.added.append(item)


def test_reconcile_session_task_progress_keeps_stage_running_while_pending_reverify() -> None:
    session = SimpleNamespace(
        last_task_id="task-1",
        asset_id="asset-1",
        summary_json={"running_stage_code": "remove_exposure", "completed_stage_codes": []},
        updated_at=None,
    )
    task = SimpleNamespace(
        id="task-1",
        task_type=TaskType.REMEDIATION_EXECUTE,
        scope_type="asset",
        scope_id="asset-1",
        status=TaskExecutionStatus.SUCCESS,
        result_json={
            "context": {"stage_code": "remove_exposure"},
            "execution": {"execution_mode": "apply"},
            "business_status": BUSINESS_STATUS_PENDING_REVERIFY,
        },
    )
    db = _FakeDB(task)

    _reconcile_session_task_progress(db, session)

    assert session.summary_json["running_stage_code"] == "remove_exposure"
    assert session.summary_json["completed_stage_codes"] == []


def test_reconcile_session_task_progress_marks_stage_completed_only_after_verified_closed() -> None:
    session = SimpleNamespace(
        last_task_id="task-1",
        asset_id="asset-1",
        summary_json={"running_stage_code": "remove_exposure", "completed_stage_codes": []},
        updated_at=None,
    )
    task = SimpleNamespace(
        id="task-1",
        task_type=TaskType.REMEDIATION_EXECUTE,
        scope_type="asset",
        scope_id="asset-1",
        status=TaskExecutionStatus.SUCCESS,
        result_json={
            "context": {"stage_code": "remove_exposure"},
            "execution": {"execution_mode": "apply"},
            "business_status": BUSINESS_STATUS_VERIFIED_CLOSED,
        },
    )
    db = _FakeDB(task)

    _reconcile_session_task_progress(db, session)

    assert session.summary_json["running_stage_code"] is None
    assert session.summary_json["completed_stage_codes"] == ["remove_exposure"]
