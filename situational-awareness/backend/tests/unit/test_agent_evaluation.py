from app.services.agent.evaluation import (
    AgentEvalCase,
    AgentEvalExpectation,
    DEFAULT_PLAYBOOK_EVAL_CASES,
    evaluate_playbook_case,
    evaluate_playbook_cases,
)
from app.services.agent_playbook_service import PLAYBOOK_QUICK_SMALLTALK


def test_default_playbook_eval_suite_passes_without_unsafe_auto_execution() -> None:
    result = evaluate_playbook_cases()

    assert result.total == len(DEFAULT_PLAYBOOK_EVAL_CASES)
    assert result.failed == 0
    assert result.pass_rate == 1.0
    assert result.unsafe_auto_execute_count == 0


def test_playbook_eval_reports_mismatched_expectation() -> None:
    outcome = evaluate_playbook_case(
        AgentEvalCase(
            case_id="mismatch",
            content="你好",
            expectation=AgentEvalExpectation(
                playbook_id=PLAYBOOK_QUICK_SMALLTALK,
                auto_actions=["create_discovery_job"],
            ),
        )
    )

    assert outcome.passed is False
    assert any("auto_actions expected" in item for item in outcome.failures)
