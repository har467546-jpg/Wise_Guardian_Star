from contextlib import contextmanager
from types import SimpleNamespace

from app.tasks import scan_tasks


@contextmanager
def _fake_tracked_task(*args, **kwargs):
    yield SimpleNamespace(id=args[0] if args else "task-1")


def test_run_asset_scan_task_uses_refactored_network_only_pipeline(monkeypatch) -> None:
    calls: list[str] = []
    stage_codes: list[str | None] = []

    monkeypatch.setattr(scan_tasks, "tracked_task", _fake_tracked_task)
    monkeypatch.setattr(scan_tasks, "ensure_task_not_canceled", lambda task_run_id: None)
    monkeypatch.setattr(scan_tasks, "discover_hosts", lambda job_id: calls.append("discover_hosts") or job_id)
    monkeypatch.setattr(scan_tasks, "upsert_assets", lambda job_id: calls.append("upsert_assets") or job_id)
    monkeypatch.setattr(scan_tasks, "get_discovery_basic_stats", lambda job_id: {"host_count": 3, "excluded_local_ip_count": 1})
    monkeypatch.setattr(scan_tasks, "_queue_followup_asset_scan_task", lambda job_id: calls.append("queue_followup") or "task-followup-1")
    monkeypatch.setattr(
        scan_tasks,
        "set_task_progress",
        lambda task_run_id, progress, message, result_json, *, stage_code=None, stage_name=None: stage_codes.append(stage_code),
    )
    monkeypatch.setattr(
        scan_tasks,
        "set_task_success",
        lambda task_run_id, message, result_json=None: calls.append(("set_task_success", message, result_json)),
    )

    fake_task = SimpleNamespace(
        request=SimpleNamespace(id="celery-task-1", retries=0),
        max_retries=3,
        retry=lambda *args, **kwargs: None,
    )

    result = scan_tasks.run_asset_scan_task.run.__func__(fake_task, "task-run-1", "job-1")

    assert result == "task-run-1"
    assert calls == [
        "discover_hosts",
        "upsert_assets",
        "queue_followup",
        ("set_task_success", "基础信息扫描完成", {"job_id": "job-1", "scan_phase": "baseline", "followup_task_id": "task-followup-1", "host_count": 3, "excluded_local_ip_count": 1}),
    ]
    assert stage_codes == [
        "discover_hosts",
        "upsert_assets",
        "queue_deep_scan",
    ]


def test_run_asset_scan_followup_task_executes_deep_scan_pipeline(monkeypatch) -> None:
    calls: list[str] = []
    stage_codes: list[str | None] = []

    monkeypatch.setattr(scan_tasks, "tracked_task", _fake_tracked_task)
    monkeypatch.setattr(scan_tasks, "ensure_task_not_canceled", lambda task_run_id: None)
    monkeypatch.setattr(scan_tasks, "full_port_scan", lambda job_id: calls.append("full_port_scan") or job_id)
    monkeypatch.setattr(scan_tasks, "probe_open_services", lambda job_id: calls.append("probe_open_services") or job_id)
    monkeypatch.setattr(scan_tasks, "evaluate_risks", lambda job_id: calls.append("evaluate_risks") or job_id)
    monkeypatch.setattr(scan_tasks, "finalize_job", lambda job_id: calls.append("finalize_job") or job_id)
    monkeypatch.setattr(scan_tasks, "get_discovery_scan_stats", lambda job_id: {"open_port_count": 2})
    monkeypatch.setattr(
        scan_tasks,
        "set_task_progress",
        lambda task_run_id, progress, message, result_json, *, stage_code=None, stage_name=None: stage_codes.append(stage_code),
    )
    monkeypatch.setattr(
        scan_tasks,
        "set_task_success",
        lambda task_run_id, message, result_json=None: calls.append(("set_task_success", message, result_json)),
    )

    fake_task = SimpleNamespace(
        request=SimpleNamespace(id="celery-task-2", retries=0),
        max_retries=3,
        retry=lambda *args, **kwargs: None,
    )

    result = scan_tasks.run_asset_scan_followup_task.run.__func__(fake_task, "task-run-2", "job-2")

    assert result == "task-run-2"
    assert calls == [
        "full_port_scan",
        "probe_open_services",
        "evaluate_risks",
        "finalize_job",
        ("set_task_success", "深度扫描与风险验证完成", {"job_id": "job-2", "scan_phase": "deep", "open_port_count": 2}),
    ]
    assert stage_codes == [
        "full_port_scan",
        "probe_open_services",
        "queue_risk_verification",
        "finalize_job",
    ]
