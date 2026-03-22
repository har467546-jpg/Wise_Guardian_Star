import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import consume_runtime_bootstrap_marker, settings
from app.core.logging import configure_logging
from app.db.base import Base
from app.db import models as db_models  # noqa: F401
from app.db.session import SessionLocal, engine
from app.services.device_alert_service import device_alert_hub
from app.services.local_asset_service import purge_local_assets
from app.services.platform_log_service import disable_platform_log_capture, enable_platform_log_capture, install_platform_log_capture
from app.utils.local_asset import remember_local_asset_hint

_LOCAL_ASSET_PURGE_COMPLETED = False
_REMOVED_VULN_LIBRARY_TASKS_PURGED = False


def _purge_removed_vuln_library_tasks(logger: logging.Logger) -> None:
    global _REMOVED_VULN_LIBRARY_TASKS_PURGED
    if _REMOVED_VULN_LIBRARY_TASKS_PURGED:
        return
    with engine.begin() as conn:
        deleted_events = conn.execute(
            text(
                """
                DELETE FROM task_events
                WHERE task_run_id IN (
                    SELECT id
                    FROM task_runs
                    WHERE task_type::text IN ('vuln_library_ai_preview', 'vuln_library_ai_apply')
                )
                """
            )
        )
        deleted_runs = conn.execute(
            text(
                """
                DELETE FROM task_runs
                WHERE task_type::text IN ('vuln_library_ai_preview', 'vuln_library_ai_apply')
                """
            )
        )
    _REMOVED_VULN_LIBRARY_TASKS_PURGED = True
    if (deleted_runs.rowcount or 0) or (deleted_events.rowcount or 0):
        logger.info(
            "Purged removed vuln-library AI task history: %s task_runs, %s task_events",
            int(deleted_runs.rowcount or 0),
            int(deleted_events.rowcount or 0),
        )


def create_app() -> FastAPI:
    configure_logging()
    install_platform_log_capture(service_name="backend")
    logger = logging.getLogger(__name__)
    if consume_runtime_bootstrap_marker():
        logger.info(
            "Auto-initialized runtime ENCRYPTION_KEY at %s",
            settings.model_config.get("env_file", ("backend/.env.runtime",))[0],
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        platform_log_capture_enabled = False
        try:
            Base.metadata.create_all(bind=engine)
            _purge_removed_vuln_library_tasks(logger)
            enable_platform_log_capture()
            platform_log_capture_enabled = True
        except Exception as exc:  # pragma: no cover - environment dependent
            logger.warning("Database initialization skipped: %s", exc)
            disable_platform_log_capture()
        try:
            await device_alert_hub.start()
        except Exception as exc:  # pragma: no cover - environment dependent
            logger.warning("Device alert hub startup skipped: %s", exc)
        try:
            yield
        finally:
            if platform_log_capture_enabled:
                disable_platform_log_capture()
            await device_alert_hub.stop()

    app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)
    if settings.CORS_ALLOW_ALL:
        cors_allow_origins = ["*"]
        cors_allow_credentials = False
        logger.info("CORS running in development allow-all mode")
    else:
        cors_allow_origins = [origin.strip() for origin in settings.CORS_ALLOW_ORIGINS.split(",") if origin.strip()]
        cors_allow_credentials = True
        logger.info("CORS allowlist mode enabled for origins: %s", cors_allow_origins)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_allow_origins,
        allow_credentials=cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(RequestValidationError)
    async def log_request_validation_error(request: Request, exc: RequestValidationError):
        body_preview = None
        if request.url.path.startswith(f"{settings.API_V1_PREFIX}/runner/tasks/"):
            try:
                body_preview = (await request.body()).decode("utf-8", errors="replace")[:4000]
            except Exception:  # pragma: no cover - defensive logging only
                body_preview = "<unavailable>"
        logger.warning(
            "Request validation failed for %s %s: errors=%s%s",
            request.method,
            request.url.path,
            exc.errors(),
            f", body_preview={body_preview}" if body_preview is not None else "",
        )
        return await request_validation_exception_handler(request, exc)

    @app.middleware("http")
    async def capture_runtime_local_asset_hints(request: Request, call_next):
        global _LOCAL_ASSET_PURGE_COMPLETED
        learned_new_hint = False
        for header_name in (
            "x-platform-host",
            "x-platform-origin",
            "origin",
            "referer",
            "x-forwarded-host",
            "host",
        ):
            if remember_local_asset_hint(request.headers.get(header_name)):
                learned_new_hint = True

        if learned_new_hint or not _LOCAL_ASSET_PURGE_COMPLETED:
            with SessionLocal() as db:
                try:
                    removed_assets = purge_local_assets(db)
                    if removed_assets:
                        db.commit()
                        logger.info(
                            "Purged %s local assets after learning platform address: %s",
                            len(removed_assets),
                            ", ".join(item["ip"] or "" for item in removed_assets),
                        )
                    _LOCAL_ASSET_PURGE_COMPLETED = True
                except Exception as exc:  # pragma: no cover - environment dependent
                    db.rollback()
                    logger.warning("Failed to purge local assets after learning runtime hint: %s", exc)
        return await call_next(request)

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
