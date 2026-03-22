from app.schemas.remediation import HostRemediationPlanStepRead, RemediationBlockerRead
from app.services.remediation_session_service import _assign_host_plan_step_ids


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
