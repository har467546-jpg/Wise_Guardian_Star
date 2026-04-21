from app.services.remediation_evidence_service import build_remediation_evidence
from app.services.remediation_executor import (
    _extract_package_transaction_id,
    _parse_package_context_snapshot_line,
    _select_package_context_snapshot,
)


def test_parse_package_context_snapshot_line_returns_structured_package_context() -> None:
    parsed = _parse_package_context_snapshot_line("rpm|openssh-server|1:8.7p1-40.el9|x86_64|installed")

    assert parsed == {
        "manager": "rpm",
        "package_name": "openssh-server",
        "version": "1:8.7p1-40.el9",
        "arch": "x86_64",
        "state": "installed",
        "installed": True,
    }


def test_select_package_context_snapshot_prefers_named_package() -> None:
    selected = _select_package_context_snapshot(
        [
            "rpm|sudo|1:1.9.5p2-3.el9|x86_64|installed",
            "rpm|openssh-server|1:8.7p1-38.el9|x86_64|installed",
        ],
        package_name="openssh-server",
    )

    assert selected is not None
    assert selected["package_name"] == "openssh-server"
    assert selected["version"] == "1:8.7p1-38.el9"


def test_extract_package_transaction_id_reads_runner_marker() -> None:
    transaction_id = _extract_package_transaction_id(
        [
            "Downloading packages...",
            "SA_TRANSACTION_ID=147",
            "Complete!",
        ]
    )

    assert transaction_id == "147"


def test_build_remediation_evidence_keeps_rollback_artifact_in_execution_item() -> None:
    evidence = build_remediation_evidence(
        task_id="task-1",
        plan={"summary": "升级软件包"},
        selected_steps=[
            {
                "step_id": "step-1",
                "title": "升级 openssh-server",
                "action_type": "upgrade_package",
                "generated_command": "dnf install -y openssh-server-1:8.7p1-40.el9",
                "rollback_command": "dnf downgrade -y openssh-server-1:8.7p1-38.el9",
                "risk_level": "high",
                "idempotent": True,
                "dry_run_supported": True,
                "rollback_supported": True,
                "requires_maintenance_window": True,
                "adapter_id": "linux.package.upgrade",
                "adapter_version": "test-adapter",
                "target_files": [],
                "target_services": ["ssh"],
                "target_paths": [],
                "backup_plan": {"kind": "package_context", "targets": ["rpm:openssh-server"]},
                "verify_items": ["确认 openssh-server 版本已更新"],
                "execution_state": "ready",
            }
        ],
        execution_mode="apply",
        execution_boundary="template_generated",
        step_results=[
            {
                "step_id": "step-1",
                "title": "升级 openssh-server",
                "status": "success",
                "generated_command": "dnf install -y openssh-server-1:8.7p1-40.el9",
                "rollback_command": "dnf downgrade -y openssh-server-1:8.7p1-38.el9",
                "rollback_artifact": {
                    "kind": "package_version_replay",
                    "package_name": "openssh-server",
                    "manager": "rpm",
                    "rollback_version": "1:8.7p1-38.el9",
                    "transaction_id": "147",
                    "rollback_command": "dnf downgrade -y openssh-server-1:8.7p1-38.el9",
                },
                "exit_status": 0,
                "backup_paths": ["rpm|openssh-server|1:8.7p1-38.el9|x86_64|installed"],
                "output_tail": ["SA_TRANSACTION_ID=147"],
                "started_at": "2026-04-21T00:00:00Z",
                "finished_at": "2026-04-21T00:01:00Z",
                "error": None,
            }
        ],
    )

    execution_item = next(item for item in evidence["items"] if item["item_type"] == "step_execution")
    assert execution_item["payload_json"]["rollback_command"] == "dnf downgrade -y openssh-server-1:8.7p1-38.el9"
    assert execution_item["payload_json"]["rollback_artifact"]["transaction_id"] == "147"
