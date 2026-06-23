from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter
from typing import Any
from uuid import uuid4

from app.services.agent.dlp import redact_sensitive_payload, redact_sensitive_text
from app.utils.sanitize import sanitize_json_value, sanitize_text


@dataclass(slots=True)
class HaorTurnTrace:
    turn_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    model_calls: list[dict[str, Any]] = field(default_factory=list)
    read_tools: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    outcome: dict[str, Any] = field(default_factory=dict)


def new_trace(turn_id: str | None = None) -> HaorTurnTrace:
    return HaorTurnTrace(turn_id=str(turn_id or f"turn-{uuid4().hex[:12]}"))


def start_timer() -> float:
    return perf_counter()


def elapsed_ms(started_at: float) -> int:
    return max(0, int((perf_counter() - started_at) * 1000))


def estimate_tokens(text: str) -> int:
    normalized = str(text or "")
    if not normalized:
        return 0
    return max(1, (len(normalized) + 3) // 4)


def record_model_call(
    trace: HaorTurnTrace | None,
    *,
    provider_name: str,
    model: str,
    wire_api: str,
    latency_ms: int,
    request_text: str,
    response_text: str,
    parsed: bool,
    error: str | None = None,
) -> None:
    if trace is None:
        return
    trace.model_calls.append(
        {
            "provider": sanitize_text(provider_name, max_length=64, single_line=True) or "unknown",
            "model": sanitize_text(model, max_length=128, single_line=True) or None,
            "wire_api": sanitize_text(wire_api, max_length=32, single_line=True) or None,
            "latency_ms": max(0, int(latency_ms)),
            "input_tokens_estimate": estimate_tokens(request_text),
            "output_tokens_estimate": estimate_tokens(response_text),
            "parsed": bool(parsed),
            "error": redact_sensitive_text(error, max_length=240) if error else None,
        }
    )


def record_read_tool(trace: HaorTurnTrace | None, tool_trace: dict[str, Any], *, latency_ms: int | None = None) -> None:
    if trace is None:
        return
    payload = redact_sensitive_payload(tool_trace if isinstance(tool_trace, dict) else {})
    if latency_ms is not None:
        payload["latency_ms"] = max(0, int(latency_ms))
    trace.read_tools.append(payload)


def record_action(trace: HaorTurnTrace | None, action_result: dict[str, Any], *, latency_ms: int | None = None) -> None:
    if trace is None:
        return
    payload = redact_sensitive_payload(action_result if isinstance(action_result, dict) else {})
    if latency_ms is not None:
        payload["latency_ms"] = max(0, int(latency_ms))
    trace.actions.append(payload)


def finalize_trace(
    trace: HaorTurnTrace | None,
    *,
    status: str,
    decision_state: str | None = None,
    stop_reason: str | None = None,
    end_to_end_success: bool | None = None,
) -> dict[str, Any]:
    if trace is None:
        return {}
    total_latency_ms = max(0, int((datetime.now(timezone.utc) - trace.started_at).total_seconds() * 1000))
    model_latency_ms = sum(int(item.get("latency_ms") or 0) for item in trace.model_calls)
    tool_latency_ms = sum(int(item.get("latency_ms") or 0) for item in trace.read_tools)
    action_latency_ms = sum(int(item.get("latency_ms") or 0) for item in trace.actions)
    input_tokens = sum(int(item.get("input_tokens_estimate") or 0) for item in trace.model_calls)
    output_tokens = sum(int(item.get("output_tokens_estimate") or 0) for item in trace.model_calls)
    trace.outcome = {
        "status": sanitize_text(status, max_length=32, single_line=True) or "unknown",
        "decision_state": sanitize_text(decision_state, max_length=32, single_line=True) if decision_state else None,
        "stop_reason": sanitize_text(stop_reason, max_length=120, single_line=True) if stop_reason else None,
        "end_to_end_success": bool(end_to_end_success) if end_to_end_success is not None else None,
        "total_latency_ms": total_latency_ms,
        "model_latency_ms": model_latency_ms,
        "tool_latency_ms": tool_latency_ms,
        "action_latency_ms": action_latency_ms,
        "model_call_count": len(trace.model_calls),
        "read_tool_count": len(trace.read_tools),
        "action_count": len(trace.actions),
        "input_tokens_estimate": input_tokens,
        "output_tokens_estimate": output_tokens,
        "total_tokens_estimate": input_tokens + output_tokens,
        "cost_basis": "estimated_tokens",
        "cost_units_estimate": input_tokens + output_tokens,
    }
    return {
        "turn_id": trace.turn_id,
        "started_at": trace.started_at.isoformat(),
        "model_calls": redact_sensitive_payload(trace.model_calls),
        "read_tools": redact_sensitive_payload(trace.read_tools),
        "actions": redact_sensitive_payload(trace.actions),
        "outcome": redact_sensitive_payload(trace.outcome),
    }


def append_trace_payload(agent_state_json: dict[str, Any] | None, trace_payload: dict[str, Any]) -> dict[str, Any]:
    state = redact_sensitive_payload(agent_state_json if isinstance(agent_state_json, dict) else {})
    if not trace_payload:
        return state
    traces = state.get("traces") if isinstance(state.get("traces"), list) else []
    traces = [item for item in traces if isinstance(item, dict)]
    traces.append(sanitize_json_value(trace_payload))
    state["traces"] = redact_sensitive_payload(traces[-20:])
    state["last_trace"] = redact_sensitive_payload(trace_payload)
    state["metrics"] = redact_sensitive_payload(trace_payload.get("outcome") if isinstance(trace_payload.get("outcome"), dict) else {})
    return state
