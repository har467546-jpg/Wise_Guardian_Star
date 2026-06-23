from datetime import datetime, timedelta, timezone

from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.task_event import TaskEvent
from app.db.models.task_run import TaskRun
from app.schemas.task import TaskRunRead
from app.services.task_observability_service import serialize_task_detail, serialize_task_event, serialize_task_run


def test_serialize_task_detail_builds_stage_timings_from_events() -> None:
    base = datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc)
    task = TaskRun(
        id="task-1",
        task_type=TaskType.ASSET_SCAN,
        status=TaskExecutionStatus.SUCCESS,
        progress=100,
        message="扫描流水线完成",
        retry_count=0,
        result_json={"job_id": "job-1"},
        error_json={},
        created_at=base,
        started_at=base + timedelta(seconds=5),
        finished_at=base + timedelta(seconds=35),
        updated_at=base + timedelta(seconds=35),
    )
    events = [
        TaskEvent(
            id="evt-1",
            task_run_id=task.id,
            event_type="stage",
            level="info",
            stage_code="discover_hosts",
            stage_name="主机发现",
            message="主机发现中",
            progress=5,
            payload_json={},
            created_at=base + timedelta(seconds=10),
        ),
        TaskEvent(
            id="evt-2",
            task_run_id=task.id,
            event_type="stage",
            level="info",
            stage_code="probe_open_services",
            stage_name="开放端口探测",
            message="开放端口探测中",
            progress=60,
            payload_json={},
            created_at=base + timedelta(seconds=20),
        ),
    ]

    detail = serialize_task_detail(task, events=events, now=base + timedelta(seconds=40))

    assert detail["timing"]["queue_duration_ms"] == 5000
    assert detail["timing"]["run_duration_ms"] == 30000
    assert detail["timing"]["total_duration_ms"] == 35000
    assert detail["timing"]["current_stage_code"] == "probe_open_services"
    assert detail["timing"]["current_stage_duration_ms"] == 15000
    assert len(detail["stage_timings"]) == 2
    assert detail["stage_timings"][0]["duration_ms"] == 10000
    assert detail["stage_timings"][1]["duration_ms"] == 15000
    assert detail["event_count"] == 2


def test_serialize_task_run_includes_dispatch_columns_for_schema_validation() -> None:
    base = datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc)
    task = TaskRun(
        id="task-dispatch-1",
        task_type=TaskType.ASSET_SCAN,
        status=TaskExecutionStatus.RUNNING,
        scope_type="discovery_job",
        scope_id="job-1",
        celery_task_id="celery-1",
        execution_boundary="runner_dispatch",
        runner_asset_id="asset-runner-1",
        scanner_zone_id="zone-1",
        progress=20,
        message="扫描中",
        retry_count=0,
        result_json={},
        error_json={},
        created_at=base,
        started_at=base,
        finished_at=None,
        updated_at=base,
    )

    payload = serialize_task_run(task, events=[], now=base)
    read = TaskRunRead.model_validate(payload)

    assert read.execution_boundary == "runner_dispatch"
    assert read.runner_asset_id == "asset-runner-1"
    assert read.scanner_zone_id == "zone-1"


def test_serialize_task_detail_falls_back_when_no_events_exist() -> None:
    base = datetime(2026, 3, 14, 11, 0, tzinfo=timezone.utc)
    task = TaskRun(
        id="task-legacy-1",
        task_type=TaskType.INFO_COLLECT,
        status=TaskExecutionStatus.RUNNING,
        progress=60,
        message="正在写入采集结果",
        retry_count=0,
        result_json={"asset_id": "asset-1"},
        error_json={},
        created_at=base,
        started_at=base + timedelta(seconds=3),
        finished_at=None,
        updated_at=base + timedelta(seconds=20),
    )

    detail = serialize_task_detail(task, events=[], now=base + timedelta(seconds=23))

    assert detail["timing"]["has_event_logs"] is False
    assert detail["timing"]["queue_duration_ms"] == 3000
    assert detail["timing"]["run_duration_ms"] == 20000
    assert detail["timing"]["total_duration_ms"] == 23000
    assert detail["timing"]["current_stage_name"] == "正在写入采集结果"
    assert detail["stage_timings"] == []
    assert detail["event_count"] == 3


def test_serialize_task_detail_supports_canceled_terminal_timing() -> None:
    base = datetime(2026, 3, 14, 12, 0, tzinfo=timezone.utc)
    task = TaskRun(
        id="task-canceled-1",
        task_type=TaskType.INFO_COLLECT,
        status=TaskExecutionStatus.CANCELED,
        progress=35,
        message="任务已中断",
        retry_count=0,
        result_json={},
        error_json={},
        created_at=base,
        started_at=base + timedelta(seconds=4),
        finished_at=base + timedelta(seconds=16),
        updated_at=base + timedelta(seconds=16),
    )

    detail = serialize_task_detail(task, events=[], now=base + timedelta(seconds=20))

    assert detail["timing"]["queue_duration_ms"] == 4000
    assert detail["timing"]["run_duration_ms"] == 12000
    assert detail["timing"]["total_duration_ms"] == 16000
    assert detail["timing"]["has_event_logs"] is False
    assert detail["event_count"] == 3


def test_serialize_task_detail_makes_datetime_and_enum_fields_json_safe() -> None:
    base = datetime(2026, 3, 16, 8, 0, tzinfo=timezone.utc)
    task = TaskRun(
        id="task-json-safe-1",
        task_type=TaskType.ASSET_SCAN,
        status=TaskExecutionStatus.SUCCESS,
        progress=100,
        message="扫描完成",
        retry_count=0,
        result_json={"finished_at": base + timedelta(seconds=30)},
        error_json={},
        created_at=base,
        started_at=base + timedelta(seconds=5),
        finished_at=base + timedelta(seconds=30),
        updated_at=base + timedelta(seconds=30),
    )

    detail = serialize_task_detail(task, events=[], now=base + timedelta(seconds=30))

    assert detail["task_type"] == "asset_scan"
    assert detail["status"] == "success"
    assert detail["created_at"] == base.isoformat()
    assert detail["started_at"] == (base + timedelta(seconds=5)).isoformat()
    assert detail["finished_at"] == (base + timedelta(seconds=30)).isoformat()
    assert detail["updated_at"] == (base + timedelta(seconds=30)).isoformat()
    assert detail["result_json"]["finished_at"] == (base + timedelta(seconds=30)).isoformat()
    assert detail["last_event_at"] == (base + timedelta(seconds=30)).isoformat()


def test_serialize_task_event_makes_datetime_payload_json_safe() -> None:
    base = datetime(2026, 3, 16, 9, 30, tzinfo=timezone.utc)
    task = TaskRun(
        id="task-remediation-1",
        task_type=TaskType.REMEDIATION_EXECUTE,
        status=TaskExecutionStatus.RUNNING,
        progress=50,
        message="执行修复步骤",
        retry_count=0,
        result_json={},
        error_json={},
        created_at=base,
        started_at=base,
        finished_at=None,
        updated_at=base,
    )
    event = TaskEvent(
        id="evt-remediation-1",
        task_run_id=task.id,
        event_type="stream",
        level="info",
        stage_code="execute_steps",
        stage_name="执行步骤",
        message="输出流更新",
        progress=50,
        payload_json={
            "verified_at": base,
            "nested": {"finished_at": base + timedelta(seconds=5)},
            "items": [base + timedelta(seconds=10)],
        },
        created_at=base + timedelta(seconds=1),
    )

    payload = serialize_task_event(event, task=task)

    assert payload["task_type"] == "remediation_execute"
    assert payload["status"] == "running"
    assert payload["created_at"] == (base + timedelta(seconds=1)).isoformat()
    assert payload["payload_json"]["verified_at"] == base.isoformat()
    assert payload["payload_json"]["nested"]["finished_at"] == (base + timedelta(seconds=5)).isoformat()
    assert payload["payload_json"]["items"] == [(base + timedelta(seconds=10)).isoformat()]
