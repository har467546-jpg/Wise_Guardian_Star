from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collector.ssh_collector import (
    AsyncSSHCollector,
    SSHCollectProfile,
    _build_connect_kwargs,
    _build_password_piped_command,
    _connect_with_legacy_hostkey_fallback,
    _load_asyncssh,
)
from app.core.config import settings
from app.core.crypto import decrypt_text
from app.db.models.asset import Asset
from app.db.models.credential import SSHCredential
from app.db.models.enums import CredentialAuthType
from app.db.models.risk_finding import RiskFinding
from app.schemas.remediation import RemediationExecuteStepInput
from app.services.remediation_business_service import (
    BUSINESS_STATUS_PENDING_REVERIFY,
    BUSINESS_STATUS_VERIFIED_FAILED,
    EXECUTION_STATUS_FAILED,
    EXECUTION_STATUS_PREVIEW_ONLY,
    EXECUTION_STATUS_SUCCEEDED,
    build_business_status_message,
    queue_remediation_reverify,
)
from app.services.remediation_evidence_service import build_remediation_evidence
from app.tasks.task_runtime import append_current_task_event, ensure_task_not_canceled

STREAM_LINE_LIMIT = 120
STREAM_LINE_LENGTH_LIMIT = 800
OUTPUT_TAIL_LIMIT = 60


def _stop_on_failure_enabled() -> bool:
    return bool(settings.REMEDIATION_STOP_ON_FAILURE)


def _prepare_backups_enabled() -> bool:
    return bool(settings.REMEDIATION_PREPARE_BACKUPS_ENABLED)


def _auto_reverify_enabled() -> bool:
    return bool(settings.REMEDIATION_AUTO_REVERIFY_ENABLED)


@dataclass(slots=True)
class RemediationExecutionContext:
    asset: Asset
    credential: SSHCredential
    effective_privilege: str
    task_run_id: str


class AsyncSSHRemediationExecutor:
    async def verify_authorization(self, context: RemediationExecutionContext) -> dict[str, Any]:
        profile = _build_profile(context.asset, context.credential)
        result = await AsyncSSHCollector().verify_authorization(profile)
        if not result.ok:
            raise RuntimeError(result.summary)
        if result.effective_privilege not in {"root", "sudo"}:
            raise RuntimeError("当前 SSH 凭据未验证到管理员权限")
        return result.to_dict()

    async def execute(
        self,
        *,
        context: RemediationExecutionContext,
        steps: list[dict[str, Any]],
        submitted_steps: list[RemediationExecuteStepInput],
    ) -> dict[str, Any]:
        profile = _build_profile(context.asset, context.credential)
        asyncssh = _load_asyncssh()
        connect_kwargs = _build_connect_kwargs(asyncssh=asyncssh, profile=profile, options=_default_collect_options())
        if connect_kwargs is None:
            raise RuntimeError("SSH 凭据内容无效，无法建立修复连接")

        submitted_step_ids = {item.step_id for item in submitted_steps}

        async with _connect_with_legacy_hostkey_fallback(asyncssh=asyncssh, connect_kwargs=connect_kwargs) as connection:
            step_results: list[dict[str, Any]] = []
            backup_map: dict[str, list[str]] = {}
            success_count = 0
            executed_count = 0
            for index, step in enumerate(steps, start=1):
                ensure_task_not_canceled(context.task_run_id)
                if submitted_step_ids and str(step.get("step_id")) not in submitted_step_ids:
                    continue
                result = await self._execute_step(
                    connection=connection,
                    context=context,
                    step=step,
                    step_index=index,
                )
                step_results.append(result)
                if result["status"] == "success":
                    success_count += 1
                    executed_count += 1
                elif result["status"] == "failed":
                    executed_count += 1
                    backup_map[result["step_id"]] = result.get("backup_paths", [])
                    if _stop_on_failure_enabled():
                        break
                if result.get("backup_paths"):
                    backup_map[result["step_id"]] = result.get("backup_paths", [])
            failed_count = sum(1 for item in step_results if item.get("status") == "failed")
            blocked_count = sum(1 for item in step_results if item.get("status") == "blocked")
            skipped_count = sum(1 for item in step_results if item.get("status") == "skipped")
            return {
                "execution_boundary": "template_generated",
                "step_results": step_results,
                "success_count": success_count,
                "executed_count": executed_count,
                "failed_count": failed_count,
                "blocked_count": blocked_count,
                "skipped_count": skipped_count,
                "backup_map": backup_map,
            }

    async def _execute_step(
        self,
        *,
        connection: Any,
        context: RemediationExecutionContext,
        step: dict[str, Any],
        step_index: int,
    ) -> dict[str, Any]:
        step_id = str(step.get("step_id") or f"step-{step_index}")
        title = str(step.get("title") or step_id)
        generated_command = str(step.get("generated_command") or "").strip() or None
        execution_state = str(step.get("execution_state") or "").strip().lower()
        supported = bool(step.get("supported"))
        if execution_state == "blocked":
            return {
                "step_id": step_id,
                "title": title,
                "status": "blocked",
                "generated_command": generated_command,
                "exit_status": None,
                "backup_paths": [],
                "output_tail": [],
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "error": str(step.get("blocked_reason") or step.get("render_reason") or "步骤被阻塞"),
            }
        if not supported or not generated_command:
            return {
                "step_id": step_id,
                "title": title,
                "status": "skipped",
                "generated_command": generated_command,
                "exit_status": None,
                "backup_paths": [],
                "output_tail": [],
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "error": None,
            }

        append_current_task_event(
            event_type="command",
            stage_code="execute_steps",
            stage_name="执行修复步骤",
            message=f"执行步骤 {step_index}: {title}",
            payload_json={
                "step_id": step_id,
                "title": title,
                "generated_command": generated_command,
                "submitted_command": generated_command,
            },
        )

        backup_paths = await self._prepare_backups(connection=connection, context=context, step=step, step_id=step_id)
        started_at = datetime.now(timezone.utc)
        actual_command = _wrap_remote_command(
            command_body=generated_command,
            privilege=context.effective_privilege,
            sudo_password=_decrypt_optional(context.credential.sudo_secret_ciphertext),
        )
        exit_status, output_tail, error = await self._run_streaming_command(
            connection=connection,
            actual_command=actual_command,
            step_id=step_id,
        )
        finished_at = datetime.now(timezone.utc)
        status = "success" if exit_status == 0 else "failed"
        if status == "success":
            append_current_task_event(
                event_type="stage",
                stage_code="execute_steps",
                stage_name="执行修复步骤",
                message=f"步骤完成: {title}",
                payload_json={"step_id": step_id, "status": status},
            )
        else:
            append_current_task_event(
                event_type="failure",
                level="error",
                stage_code="execute_steps",
                stage_name="执行修复步骤",
                message=f"步骤失败: {title}",
                payload_json={"step_id": step_id, "status": status, "error": error, "exit_status": exit_status},
            )
        return {
            "step_id": step_id,
            "title": title,
            "status": status,
            "generated_command": generated_command,
            "exit_status": exit_status,
            "backup_paths": backup_paths,
            "output_tail": output_tail,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "error": error,
        }

    async def _prepare_backups(
        self,
        *,
        connection: Any,
        context: RemediationExecutionContext,
        step: dict[str, Any],
        step_id: str,
    ) -> list[str]:
        backup_plan = step.get("backup_plan") if isinstance(step.get("backup_plan"), dict) else {}
        kind = str(backup_plan.get("kind") or "").strip().lower()
        targets = [str(item).strip() for item in backup_plan.get("targets", []) if str(item).strip()]
        if not _prepare_backups_enabled() or not kind or not targets:
            return []
        append_current_task_event(
            event_type="stage",
            stage_code="prepare_backups",
            stage_name="备份准备",
            message=f"准备步骤备份: {step_id}",
            payload_json={"step_id": step_id, "kind": kind, "targets": targets},
        )
        if kind == "file_copy":
            created: list[str] = []
            for target in targets:
                actual = _wrap_remote_command(
                    command_body=_build_copy_backup_command(target),
                    privilege=context.effective_privilege,
                    sudo_password=_decrypt_optional(context.credential.sudo_secret_ciphertext),
                )
                result = await connection.run(actual, check=False)
                if getattr(result, "exit_status", 1) == 0:
                    backup_path = str(getattr(result, "stdout", "") or "").strip()
                    if backup_path:
                        created.append(backup_path)
            return created
        if kind == "permission_snapshot":
            snapshots: list[str] = []
            for target in targets:
                actual = _wrap_remote_command(
                    command_body=f"stat -c '%n|%a|%U|%G' {shlex.quote(target)}",
                    privilege=context.effective_privilege,
                    sudo_password=_decrypt_optional(context.credential.sudo_secret_ciphertext),
                )
                result = await connection.run(actual, check=False)
                if getattr(result, "exit_status", 1) == 0:
                    line = str(getattr(result, "stdout", "") or "").strip()
                    if line:
                        snapshots.append(line)
            return snapshots
        return []

    async def _run_streaming_command(self, *, connection: Any, actual_command: str, step_id: str) -> tuple[int, list[str], str | None]:
        output_tail: list[str] = []
        emitted_lines = 0
        truncated = False
        if hasattr(connection, "create_process"):
            process = await connection.create_process(actual_command)
            async def _pump(reader: Any, stream_name: str) -> None:
                nonlocal emitted_lines, truncated
                while True:
                    line = await reader.readline()
                    if not line:
                        break
                    text = str(line).rstrip("\n")
                    if text:
                        if len(output_tail) >= OUTPUT_TAIL_LIMIT:
                            output_tail.pop(0)
                        output_tail.append(text[:STREAM_LINE_LENGTH_LIMIT])
                    if emitted_lines < STREAM_LINE_LIMIT:
                        append_current_task_event(
                            event_type="stream",
                            stage_code="execute_steps",
                            stage_name="执行修复步骤",
                            message=text[:255],
                            payload_json={"step_id": step_id, "stream": stream_name, "text": text[:STREAM_LINE_LENGTH_LIMIT]},
                        )
                        emitted_lines += 1
                    else:
                        truncated = True
            await asyncio.gather(_pump(process.stdout, "stdout"), _pump(process.stderr, "stderr"))
            await process.wait_closed()
            exit_status = int(getattr(process, "exit_status", 1) or 0)
            stderr = getattr(process, "stderr", None)
            error = None if exit_status == 0 else _extract_process_error(stderr, output_tail)
        else:
            result = await connection.run(actual_command, check=False)
            stdout = str(getattr(result, "stdout", "") or "")
            stderr = str(getattr(result, "stderr", "") or "")
            for stream_name, content in (("stdout", stdout), ("stderr", stderr)):
                for line in content.splitlines():
                    if line:
                        if len(output_tail) >= OUTPUT_TAIL_LIMIT:
                            output_tail.pop(0)
                        output_tail.append(line[:STREAM_LINE_LENGTH_LIMIT])
                    if emitted_lines < STREAM_LINE_LIMIT:
                        append_current_task_event(
                            event_type="stream",
                            stage_code="execute_steps",
                            stage_name="执行修复步骤",
                            message=line[:255],
                            payload_json={"step_id": step_id, "stream": stream_name, "text": line[:STREAM_LINE_LENGTH_LIMIT]},
                        )
                        emitted_lines += 1
                    else:
                        truncated = True
            exit_status = int(getattr(result, "exit_status", 1) or 0)
            error = None if exit_status == 0 else (stderr.strip() or stdout.strip() or f"退出状态码 {exit_status}")
        if truncated:
            output_tail.append("[输出已截断]")
        return exit_status, output_tail, error


def run_remediation_execution(
    db: Session,
    *,
    task_run_id: str,
    finding: RiskFinding,
    plan: dict[str, Any],
    submitted_steps: list[dict[str, Any]],
    execution_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    asset = db.get(Asset, finding.asset_id)
    if asset is None:
        raise RuntimeError("资产不存在")
    credential = db.scalar(select(SSHCredential).where(SSHCredential.name == f"manual-asset-{asset.id}"))
    if credential is None:
        raise RuntimeError("当前资产未配置 SSH 管理员凭据")
    context = RemediationExecutionContext(
        asset=asset,
        credential=credential,
        effective_privilege=str(credential.last_effective_privilege or "").strip().lower(),
        task_run_id=task_run_id,
    )
    execution_mode = str((execution_options or {}).get("execution_mode") or "apply").strip().lower() or "apply"
    change_ticket = str((execution_options or {}).get("change_ticket") or "").strip() or None
    maintenance_window_id = str((execution_options or {}).get("maintenance_window_id") or "").strip() or None
    selected_step_ids = {
        str(item.get("step_id") or "").strip()
        for item in submitted_steps
        if isinstance(item, dict) and str(item.get("step_id") or "").strip()
    }
    selected_steps = [
        dict(step)
        for step in (plan.get("steps") or [])
        if isinstance(step, dict) and (not selected_step_ids or str(step.get("step_id") or "").strip() in selected_step_ids)
    ]
    executor = AsyncSSHRemediationExecutor()
    authorization = asyncio.run(executor.verify_authorization(context))
    context.effective_privilege = str(authorization.get("effective_privilege") or context.effective_privilege).strip().lower()
    execution = asyncio.run(
        executor.execute(
            context=context,
            steps=list(plan.get("steps") or []),
            submitted_steps=[RemediationExecuteStepInput.model_validate(item) for item in submitted_steps],
        )
    )
    reverify = {"reverify_triggered": False, "reverify_task_id": None, "reverify_status": None}
    if _auto_reverify_enabled() and int(execution.get("success_count") or 0) > 0:
        reverify = queue_remediation_reverify(
            db,
            asset_id=asset.id,
            remediation_task_id=task_run_id,
            plan=plan,
            selected_steps=selected_steps,
            finding_id=finding.id,
        )
        append_current_task_event(
            event_type="reverify",
            stage_code="auto_reverify",
            stage_name="自动复测",
            message="修复后已自动触发业务复验",
            payload_json=reverify,
        )
    if int(execution.get("failed_count") or 0) > 0:
        overall_status = "apply_failed"
        final_message = build_business_status_message(BUSINESS_STATUS_VERIFIED_FAILED)
        execution_status = EXECUTION_STATUS_FAILED
        business_status = BUSINESS_STATUS_VERIFIED_FAILED
    elif reverify.get("reverify_triggered"):
        overall_status = "applied_pending_reverify"
        final_message = build_business_status_message(BUSINESS_STATUS_PENDING_REVERIFY)
        execution_status = EXECUTION_STATUS_SUCCEEDED
        business_status = BUSINESS_STATUS_PENDING_REVERIFY
    else:
        overall_status = "applied"
        final_message = "修复命令已执行完成"
        execution_status = EXECUTION_STATUS_SUCCEEDED
        business_status = None
    execution["execution_mode"] = execution_mode
    execution["change_ticket"] = change_ticket
    execution["maintenance_window_id"] = maintenance_window_id
    execution["overall_status"] = overall_status
    execution["final_message"] = final_message
    execution["execution_status"] = execution_status
    if business_status:
        execution["business_status"] = business_status
    evidence = build_remediation_evidence(
        task_id=task_run_id,
        plan=plan,
        selected_steps=selected_steps,
        execution_mode=execution_mode,
        execution_boundary=str(execution.get("execution_boundary") or "").strip() or None,
        step_results=list(execution.get("step_results") or []),
        reverify=reverify,
        change_ticket=change_ticket,
        maintenance_window_id=maintenance_window_id,
    )
    return {
        "context": {
            "asset_id": asset.id,
            "finding_id": finding.id,
            "rule_id": plan.get("rule_id"),
            "service_name": plan.get("service_name"),
            "authorization": authorization,
        },
        "plan": plan,
        "execution": execution,
        "execution_status": execution_status,
        "business_status": business_status,
        "backups": execution.get("backup_map") or {},
        "reverify": reverify,
        "reverify_task_id": reverify.get("reverify_task_id"),
        "reverify_summary": {},
        "targeted_finding_outcomes": [],
        "evidence": evidence,
    }


def build_remediation_preview_result(
    *,
    task_run_id: str,
    context: dict[str, Any],
    plan: dict[str, Any],
    selected_steps: list[dict[str, Any]],
    change_ticket: str | None = None,
    maintenance_window_id: str | None = None,
    stage_code: str | None = None,
    stage_name: str | None = None,
) -> dict[str, Any]:
    execution = {
        "execution_boundary": "dry_run_preview",
        "execution_mode": "dry_run",
        "submitted_steps": [{"step_id": str(item.get("step_id") or "").strip()} for item in selected_steps if str(item.get("step_id") or "").strip()],
        "success_count": 0,
        "executed_count": 0,
        "failed_count": 0,
        "blocked_count": 0,
        "skipped_count": 0,
        "overall_status": "preview_ready",
        "final_message": "修复预演已生成，尚未执行任何主机变更",
        "execution_status": EXECUTION_STATUS_PREVIEW_ONLY,
        "change_ticket": change_ticket,
        "maintenance_window_id": maintenance_window_id,
        "stage_code": stage_code,
        "stage_name": stage_name,
    }
    reverify = {"reverify_triggered": False, "reverify_task_id": None, "reverify_status": None}
    evidence = build_remediation_evidence(
        task_id=task_run_id,
        plan=plan,
        selected_steps=selected_steps,
        execution_mode="dry_run",
        execution_boundary="dry_run_preview",
        step_results=[],
        reverify=reverify,
        change_ticket=change_ticket,
        maintenance_window_id=maintenance_window_id,
        stage_code=stage_code,
        stage_name=stage_name,
    )
    return {
        "context": dict(context),
        "plan": plan,
        "execution": execution,
        "execution_status": EXECUTION_STATUS_PREVIEW_ONLY,
        "business_status": None,
        "backups": {},
        "reverify": reverify,
        "reverify_task_id": None,
        "reverify_summary": {},
        "targeted_finding_outcomes": [],
        "evidence": evidence,
    }


def _build_profile(asset: Asset, credential: SSHCredential) -> SSHCollectProfile:
    password: str | None = None
    private_key: str | None = None
    sudo_password: str | None = None
    if credential.auth_type == CredentialAuthType.PASSWORD:
        password = _decrypt_optional(credential.secret_ciphertext)
    elif credential.auth_type == CredentialAuthType.KEY:
        private_key = _decrypt_optional(credential.key_ciphertext)
    sudo_password = _decrypt_optional(credential.sudo_secret_ciphertext)
    return SSHCollectProfile(
        asset_id=asset.id,
        ip=str(asset.ip),
        username=credential.username,
        password=password,
        private_key=private_key,
        sudo_password=sudo_password,
    )


def _decrypt_optional(value: str | None) -> str | None:
    if not value:
        return None
    return decrypt_text(value)


def _wrap_remote_command(*, command_body: str, privilege: str, sudo_password: str | None) -> str:
    command = f"sh -lc {shlex.quote(command_body)}"
    if privilege == "sudo":
        if not (sudo_password or "").strip():
            raise RuntimeError("缺少 sudo 密码，无法执行修复命令")
        return _build_password_piped_command(
            f"sudo -S -p '' sh -lc {shlex.quote(command_body)}",
            sudo_password,
        )
    return command


def _build_copy_backup_command(target: str) -> str:
    target_quoted = shlex.quote(target)
    return "\n".join(
        [
            f"if [ ! -e {target_quoted} ]; then exit 0; fi",
            f"backup=$(printf %s {target_quoted}).bak.sa.$(date +%Y%m%d%H%M%S)",
            f"cp -a {target_quoted} \"$backup\"",
            'printf "%s" "$backup"',
        ]
    )
def _extract_process_error(stderr: Any, output_tail: list[str]) -> str:
    if hasattr(stderr, "read"):
        return "命令执行失败，请查看流式日志"
    if output_tail:
        return output_tail[-1]
    return "命令执行失败"


def _default_collect_options():
    from app.collector.ssh_collector import SSHCollectOptions

    return SSHCollectOptions()
