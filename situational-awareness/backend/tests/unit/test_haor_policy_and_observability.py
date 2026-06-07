from app.services.haor.action_policy import (
    ACTION_POLICIES,
    ACTION_POLICY_REGISTRY,
    AUTO_EXECUTE_ACTIONS,
    SUPPORTED_WRITE_ACTIONS,
    action_allows_auto_execute,
)
from app.services.haor.observability import (
    append_trace_payload,
    finalize_trace,
    new_trace,
    record_action,
    record_model_call,
    record_read_tool,
)


def test_action_policy_is_single_source_for_supported_and_auto_actions() -> None:
    assert SUPPORTED_WRITE_ACTIONS == frozenset(ACTION_POLICIES)
    assert AUTO_EXECUTE_ACTIONS == frozenset(
        action_type for action_type, policy in ACTION_POLICIES.items() if policy.auto_execute_allowed
    )
    assert action_allows_auto_execute("create_discovery_job") is True
    assert action_allows_auto_execute("approve_remediation_session") is False
    assert ACTION_POLICY_REGISTRY["configure_ssh_credential"]["risk_level"] == "sensitive_input"


def test_observability_trace_summarizes_latency_tokens_and_success() -> None:
    trace = new_trace("turn-test")

    record_model_call(
        trace,
        provider_name="custom_proxy",
        model="model-a",
        wire_api="responses",
        latency_ms=123,
        request_text="hello" * 20,
        response_text='{"reply_markdown":"ok"}',
        parsed=True,
    )
    record_read_tool(trace, {"tool_name": "get_asset_detail", "ok": True}, latency_ms=7)
    record_action(trace, {"action_type": "create_discovery_job", "status": "success"}, latency_ms=11)

    payload = finalize_trace(
        trace,
        status="ok",
        decision_state="answer",
        stop_reason="test",
        end_to_end_success=True,
    )
    state = append_trace_payload({}, payload)

    assert payload["outcome"]["model_latency_ms"] == 123
    assert payload["outcome"]["tool_latency_ms"] == 7
    assert payload["outcome"]["action_latency_ms"] == 11
    assert payload["outcome"]["total_tokens_estimate"] > 0
    assert payload["outcome"]["end_to_end_success"] is True
    assert state["last_trace"]["turn_id"] == "turn-test"
    assert state["metrics"]["model_call_count"] == 1
