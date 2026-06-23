from __future__ import annotations

from celery import Task

from app.core.celery_app import celery_app
from app.db.models.enums import TaskType
from app.db.session import SessionLocal
from app.repositories.task_repo import create_task_run, update_task_run
from app.services.secret_migration_service import migrate_legacy_secret_ciphertexts
from app.tasks.task_runtime import set_task_failure, set_task_progress, set_task_success, tracked_task


@celery_app.task(bind=True, name="app.tasks.secret_migration_tasks.migrate_legacy_secret_ciphertexts")
def migrate_legacy_secret_ciphertexts_task(self: Task, task_run_id: str | None = None, batch_size: int = 200) -> dict[str, int]:
    if not task_run_id:
        with SessionLocal() as db:
            task_run = create_task_run(
                db,
                task_type=TaskType.SECRET_CIPHER_MIGRATION,
                scope_type="system",
                scope_id="secrets",
                message="历史密文迁移任务已入队",
            )
            update_task_run(db, task_run, celery_task_id=str(self.request.id or ""))
            task_run_id = task_run.id
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id):
            set_task_progress(task_run_id, 10, "正在扫描历史密文")
            with SessionLocal() as db:
                result = migrate_legacy_secret_ciphertexts(db, batch_size=batch_size)
            payload = {"scanned": result.scanned, "migrated": result.migrated, "failed": result.failed}
            message = f"历史密文迁移完成：迁移 {result.migrated} 项，失败 {result.failed} 项"
            set_task_success(task_run_id, message, payload)
            return payload
    except Exception as exc:
        set_task_failure(task_run_id, 0, str(exc))
        raise
