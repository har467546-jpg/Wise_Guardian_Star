from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha1
from typing import Any


def build_remediation_evidence(
    *,
    task_id: str,
    plan: dict[str, Any],
    selected_steps: list[dict[str, Any]],
    execution_mode: str,
    execution_boundary: str | None,
    step_results: list[dict[str, Any]] | None = None,
    reverify: dict[str, Any] | None = None,
    change_ticket: str | None = None,
    maintenance_window_id: str | None = None,
    stage_code: str | None = None,
    stage_name: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    result_by_step_id = {
        str(item.get("step_id") or "").strip(): item
        for item in (step_results or [])
        if isinstance(item, dict) and str(item.get("step_id") or "").strip()
    }
    items: list[dict[str, Any]] = [
        _build_overview_item(
            execution_mode=execution_mode,
            execution_boundary=execution_boundary,
            plan=plan,
            selected_steps=selected_steps,
            change_ticket=change_ticket,
            maintenance_window_id=maintenance_window_id,
            stage_code=stage_code,
            stage_name=stage_name,
            collected_at=now,
        )
    ]
    for step in selected_steps:
        step_id = str(step.get("step_id") or "").strip()
        step_result = result_by_step_id.get(step_id)
        items.extend(
            _build_step_items(
                step=step,
                execution_mode=execution_mode,
                step_result=step_result,
                collected_at=now,
            )
        )
    if reverify:
        items.append(_build_reverify_item(reverify=reverify, collected_at=now))
    summary = {
        "selected_step_count": len(selected_steps),
        "executed_step_count": len(result_by_step_id),
        "successful_step_count": sum(1 for item in result_by_step_id.values() if str(item.get("status") or "").strip() == "success"),
        "failed_step_count": sum(1 for item in result_by_step_id.values() if str(item.get("status") or "").strip() == "failed"),
        "blocked_step_count": sum(1 for item in result_by_step_id.values() if str(item.get("status") or "").strip() == "blocked"),
        "reverify_triggered": bool((reverify or {}).get("reverify_triggered")),
    }
    return {
        "task_id": task_id,
        "execution_mode": execution_mode,
        "execution_boundary": execution_boundary,
        "generated_at": now,
        "item_count": len(items),
        "items": items,
        "summary": summary,
    }


def _build_overview_item(
    *,
    execution_mode: str,
    execution_boundary: str | None,
    plan: dict[str, Any],
    selected_steps: list[dict[str, Any]],
    change_ticket: str | None,
    maintenance_window_id: str | None,
    stage_code: str | None,
    stage_name: str | None,
    collected_at: str,
) -> dict[str, Any]:
    plan_summary = str(plan.get("summary_text") or plan.get("summary") or "修复执行概览").strip()
    title = "修复预演概览" if execution_mode == "dry_run" else "修复执行概览"
    payload_json = {
        "plan_summary": plan_summary,
        "execution_mode": execution_mode,
        "execution_boundary": execution_boundary,
        "selected_step_ids": [str(item.get("step_id") or "").strip() for item in selected_steps if str(item.get("step_id") or "").strip()],
        "change_ticket": change_ticket,
        "maintenance_window_id": maintenance_window_id,
        "stage_code": stage_code,
        "stage_name": stage_name,
    }
    return {
        "item_id": _item_id("overview", "overview"),
        "item_type": "overview",
        "step_id": None,
        "title": title,
        "status": "ready" if execution_mode == "dry_run" else "running",
        "summary": plan_summary,
        "payload_json": payload_json,
        "collected_at": collected_at,
    }


def _build_step_items(
    *,
    step: dict[str, Any],
    execution_mode: str,
    step_result: dict[str, Any] | None,
    collected_at: str,
) -> list[dict[str, Any]]:
    step_id = str(step.get("step_id") or "").strip() or "unknown-step"
    title = str(step.get("title") or step_id).strip()
    preview_payload = {
        "action_type": step.get("action_type"),
        "generated_command": step.get("generated_command"),
        "apply_supported": step.get("apply_supported"),
        "apply_blocked_reason": step.get("apply_blocked_reason"),
        "risk_level": step.get("risk_level"),
        "idempotent": step.get("idempotent"),
        "dry_run_supported": step.get("dry_run_supported"),
        "rollback_supported": step.get("rollback_supported"),
        "requires_maintenance_window": step.get("requires_maintenance_window"),
        "adapter_id": step.get("adapter_id"),
        "adapter_version": step.get("adapter_version"),
        "target_files": step.get("target_files") if isinstance(step.get("target_files"), list) else [],
        "target_services": step.get("target_services") if isinstance(step.get("target_services"), list) else [],
        "target_paths": step.get("target_paths") if isinstance(step.get("target_paths"), list) else [],
        "backup_plan": step.get("backup_plan") if isinstance(step.get("backup_plan"), dict) else {},
        "verify_items": step.get("verify_items") if isinstance(step.get("verify_items"), list) else [],
        "rollback_hint": step.get("rollback_hint"),
        "rollback_command": step.get("rollback_command"),
        "execution_state": step.get("execution_state"),
    }
    items = [
        {
            "item_id": _item_id(step_id, "preview"),
            "item_type": "step_preview",
            "step_id": step_id,
            "title": title,
            "status": "preview_ready" if execution_mode == "dry_run" else str(step.get("execution_state") or "ready"),
            "summary": _preview_summary(step),
            "payload_json": preview_payload,
            "collected_at": collected_at,
        }
    ]
    if step_result is not None:
        items.append(
            {
                "item_id": _item_id(step_id, "execution"),
                "item_type": "step_execution",
                "step_id": step_id,
                "title": title,
                "status": str(step_result.get("status") or "unknown").strip() or "unknown",
                "summary": _execution_summary(step_result),
                "payload_json": {
                    "generated_command": step_result.get("generated_command") or step.get("generated_command"),
                    "rollback_command": step_result.get("rollback_command") or step.get("rollback_command"),
                    "rollback_artifact": step_result.get("rollback_artifact") if isinstance(step_result.get("rollback_artifact"), dict) else {},
                    "exit_status": step_result.get("exit_status"),
                    "backup_paths": step_result.get("backup_paths") if isinstance(step_result.get("backup_paths"), list) else [],
                    "output_tail": step_result.get("output_tail") if isinstance(step_result.get("output_tail"), list) else [],
                    "error": step_result.get("error"),
                    "started_at": step_result.get("started_at"),
                    "finished_at": step_result.get("finished_at"),
                },
                "collected_at": collected_at,
            }
        )
    return items


def _build_reverify_item(*, reverify: dict[str, Any], collected_at: str) -> dict[str, Any]:
    task_id = str(reverify.get("reverify_task_id") or "").strip() or "-"
    status = str(reverify.get("reverify_status") or "").strip() or "not_triggered"
    summary = "修复后已自动触发复测" if reverify.get("reverify_triggered") else "当前未触发自动复测"
    return {
        "item_id": _item_id("reverify", task_id),
        "item_type": "reverify",
        "step_id": None,
        "title": "自动复测",
        "status": status,
        "summary": summary,
        "payload_json": dict(reverify),
        "collected_at": collected_at,
    }


def _preview_summary(step: dict[str, Any]) -> str:
    risk = str(step.get("risk_level") or "medium").strip()
    adapter = str(step.get("adapter_id") or "unknown-adapter").strip()
    return f"风险级别 {risk}，由 {adapter} 生成执行预演"


def _execution_summary(step_result: dict[str, Any]) -> str:
    status = str(step_result.get("status") or "unknown").strip()
    if status == "success":
        return "步骤已执行成功"
    if status == "failed":
        error = str(step_result.get("error") or "").strip()
        return error or "步骤执行失败"
    if status == "blocked":
        return str(step_result.get("error") or "步骤在执行前被阻断").strip()
    return "步骤未执行"


def _item_id(prefix: str, suffix: str) -> str:
    digest = sha1(f"{prefix}:{suffix}".encode("utf-8")).hexdigest()[:10]
    return f"{prefix}-{digest}"
