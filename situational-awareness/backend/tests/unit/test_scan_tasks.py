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
        lambda task_run_id, message, result_json=None: calls.append("set_task_success"),
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
        "full_port_scan",
        "probe_open_services",
        "evaluate_risks",
        "finalize_job",
        "set_task_success",
    ]
    assert stage_codes == [
        "discover_hosts",
        "upsert_assets",
        "full_port_scan",
        "probe_open_services",
        "queue_risk_verification",
        "finalize_job",
    ]
