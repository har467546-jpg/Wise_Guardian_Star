from __future__ import annotations

from celery import Task

from app.core.celery_app import celery_app
from app.tasks.discovery_tasks import (
    discover_hosts,
    evaluate_risks,
    finalize_job,
    full_port_scan,
    get_discovery_scan_stats,
    probe_open_services,
    upsert_assets,
)
from app.tasks.task_runtime import (
    TaskCanceledError,
    ensure_task_not_canceled,
    set_task_failure,
    set_task_progress,
    set_task_retry,
    set_task_success,
    tracked_task,
)


@celery_app.task(
    bind=True,
    name="app.tasks.scan_tasks.run_asset_scan_task",
    max_retries=3,
)
def run_asset_scan_task(self: Task, task_run_id: str, job_id: str) -> str:
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 5, "开始资产扫描", {"job_id": job_id}, stage_code="discover_hosts", stage_name="主机发现")
            discover_hosts(job_id)
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 25, "主机发现完成", {"job_id": job_id}, stage_code="upsert_assets", stage_name="资产入库")
            upsert_assets(job_id)
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 45, "资产台账已更新，开始全端口扫描", {"job_id": job_id}, stage_code="full_port_scan", stage_name="全端口扫描")
            full_port_scan(job_id)
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 60, "全端口扫描完成，开始开放端口探测", {"job_id": job_id}, stage_code="probe_open_services", stage_name="开放端口探测")
            probe_open_services(job_id)
            ensure_task_not_canceled(task_run_id)
            service_stats = get_discovery_scan_stats(job_id)
            set_task_progress(
                task_run_id,
                75,
                "开放端口探测完成",
                {"job_id": job_id, **service_stats},
                stage_code="queue_risk_verification",
                stage_name="风险验证入队",
            )
            evaluate_risks(job_id)
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 90, "风险验证任务已入队", {"job_id": job_id}, stage_code="finalize_job", stage_name="任务收尾")
            finalize_job(job_id)
            ensure_task_not_canceled(task_run_id)
            set_task_success(task_run_id, "扫描流水线完成", {"job_id": job_id, **service_stats})
    except TaskCanceledError:
        return task_run_id
    except Exception as exc:
        if self.request.retries < self.max_retries:
            set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=2 ** (self.request.retries + 1))
        set_task_failure(task_run_id, self.request.retries, str(exc))
        raise
    return task_run_id
