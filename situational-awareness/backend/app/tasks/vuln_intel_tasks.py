from __future__ import annotations

from pathlib import Path

from celery import Task
from redis import Redis
from redis.exceptions import WatchError

from app.core.celery_app import celery_app
from app.core.config import settings
from app.db.models.enums import TaskType
from app.db.session import SessionLocal
from app.repositories.task_repo import ACTIVE_TASK_STATUSES, create_task_run, get_latest_task_run_for_scope, update_task_run
from app.rules.rule_store import RuleStore
from app.services.vuln_library_service import VulnLibraryService
from app.tasks.task_runtime import set_task_failure, set_task_progress, set_task_success, tracked_task

RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "risk_rules.yaml"
RULE_STORE = RuleStore(RULES_PATH)
RULE_SERVICE = VulnLibraryService(RULE_STORE, SessionLocal)
SYNC_LOCK_KEY = "sa:vuln_intel:sync_lock"
SYNC_LOCK_TTL_SECONDS = 15 * 60


@celery_app.task(bind=True, name="app.tasks.vuln_intel_tasks.sync_vuln_intel")
def sync_vuln_intel_task(self: Task, task_run_id: str | None = None) -> dict[str, object]:
    task_run_id, reused_active_task = _ensure_task_run_id(task_run_id, celery_task_id=str(self.request.id or ""))
    if reused_active_task:
        return {"skipped": True, "reason": "vuln_intel_sync_already_running", "task_run_id": task_run_id}

    lock_token = str(self.request.id or task_run_id or "scheduled")
    lock_acquired = _acquire_sync_lock(lock_token, task_run_id=task_run_id)
    if not lock_acquired:
        payload: dict[str, object] = {"skipped": True, "reason": "vuln_intel_sync_already_running"}
        set_task_success(task_run_id, "已有漏洞情报同步任务正在运行", payload)
        return payload
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id):
            set_task_progress(task_run_id, 12, "正在同步漏洞情报", {"sources": ["cve_project", "osv", "kev", "epss"]})
            payload = _sync_intel_payload(task_run_id=task_run_id)
            set_task_success(task_run_id, "漏洞情报同步完成", payload)
            return payload
    except Exception as exc:
        set_task_failure(task_run_id, 0, str(exc))
        raise
    finally:
        _release_sync_lock(lock_token)


def _sync_intel_payload(task_run_id: str | None = None) -> dict[str, object]:
    def _progress(progress: int, message: str, payload: dict[str, object]) -> None:
        if task_run_id:
            set_task_progress(task_run_id, progress, message, payload)

    result = RULE_SERVICE.sync_intel(progress_callback=_progress if task_run_id else None)
    return {
        "tracked_rule_cves": result.tracked_rule_cves,
        "synced_cves": result.synced_cves,
        "updated_cves": result.updated_cves,
        "stale": result.stale,
        "stale_count": result.stale_count,
        "last_synced_at": result.last_synced_at.isoformat() if result.last_synced_at else None,
    }


def _ensure_task_run_id(task_run_id: str | None, *, celery_task_id: str) -> tuple[str, bool]:
    if task_run_id:
        return task_run_id, False

    with SessionLocal() as db:
        active_task = get_latest_task_run_for_scope(
            db,
            scope_type="vuln_library",
            scope_id="intel",
            task_type=TaskType.VULN_INTEL_SYNC,
            statuses=list(ACTIVE_TASK_STATUSES),
        )
        if active_task is not None:
            return active_task.id, True

        task_run = create_task_run(
            db,
            task_type=TaskType.VULN_INTEL_SYNC,
            scope_type="vuln_library",
            scope_id="intel",
            message="漏洞情报同步任务已入队",
        )
        if celery_task_id:
            update_task_run(db, task_run, celery_task_id=celery_task_id)
        return task_run.id, False


def _acquire_sync_lock(token: str, *, task_run_id: str) -> bool:
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        if client.set(SYNC_LOCK_KEY, token, nx=True, ex=SYNC_LOCK_TTL_SECONDS):
            return True
        if _has_other_active_sync_task(task_run_id):
            return False
        client.delete(SYNC_LOCK_KEY)
        return bool(client.set(SYNC_LOCK_KEY, token, nx=True, ex=SYNC_LOCK_TTL_SECONDS))
    finally:
        client.close()


def _has_other_active_sync_task(task_run_id: str) -> bool:
    with SessionLocal() as db:
        active_task = get_latest_task_run_for_scope(
            db,
            scope_type="vuln_library",
            scope_id="intel",
            task_type=TaskType.VULN_INTEL_SYNC,
            statuses=list(ACTIVE_TASK_STATUSES),
        )
        return bool(active_task and active_task.id != task_run_id)


def _release_sync_lock(token: str) -> None:
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        with client.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(SYNC_LOCK_KEY)
                    if pipe.get(SYNC_LOCK_KEY) != token:
                        pipe.unwatch()
                        return
                    pipe.multi()
                    pipe.delete(SYNC_LOCK_KEY)
                    pipe.execute()
                    return
                except WatchError:
                    continue
    finally:
        client.close()
