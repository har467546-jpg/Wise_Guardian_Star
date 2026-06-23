import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import consume_runtime_bootstrap_marker, settings
from app.core.logging import configure_logging
from app.db.base import Base
from app.db import models as db_models  # noqa: F401
from app.db.session import SessionLocal, engine
from app.services.device_alert_service import device_alert_hub
from app.services.campus_bootstrap_service import ensure_campus_auto_bootstrap
from app.services.local_asset_service import purge_local_assets
from app.services.audit_log_service import ensure_audit_log_storage, monotonic_ms, new_request_id, write_audit_log
from app.services.platform_log_service import disable_platform_log_capture, enable_platform_log_capture, install_platform_log_capture
from app.services.rate_limit_service import (
    build_rate_limit_headers,
    check_rate_limit,
    close_rate_limit_client,
    should_skip_rate_limit,
)
from app.utils.local_asset import remember_local_asset_hint

_LOCAL_ASSET_PURGE_COMPLETED = False
_REMOVED_VULN_LIBRARY_TASKS_PURGED = False


def _build_cors_allowlist(raw_origins: str) -> tuple[list[str], str | None]:
    exact_origins: list[str] = []
    wildcard_patterns: list[str] = []
    for origin in (item.strip() for item in raw_origins.split(",") if item.strip()):
        if "*" in origin:
            wildcard_patterns.append(re.escape(origin).replace(r"\*", r"[^/]+"))
        else:
            exact_origins.append(origin)
    allow_origin_regex = f"^(?:{'|'.join(wildcard_patterns)})$" if wildcard_patterns else None
    return exact_origins, allow_origin_regex


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


def _read_alembic_head_revision() -> str | None:
    versions_dir = Path(__file__).resolve().parents[1] / "alembic" / "versions"
    if not versions_dir.exists():
        return None
    revisions = sorted(item.stem.split("_", 1)[0] for item in versions_dir.glob("*.py") if item.is_file() and item.name != "__init__.py")
    return revisions[-1] if revisions else None


def _read_current_db_revision() -> str | None:
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
            row = result.first()
            if not row:
                return None
            return str(row[0] or "").strip() or None
    except Exception:
        return None


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
            if settings.AUTO_CREATE_SCHEMA:
                Base.metadata.create_all(bind=engine)
            elif settings.STRICT_SCHEMA_REVISION_CHECK:
                logger.info("AUTO_CREATE_SCHEMA disabled; expecting schema to be managed by Alembic")
                head_revision = _read_alembic_head_revision()
                current_revision = _read_current_db_revision()
                if head_revision and current_revision and head_revision != current_revision:
                    raise RuntimeError(
                        f"Database revision mismatch: current={current_revision}, expected={head_revision}. Run alembic upgrade head first."
                    )
                if head_revision:
                    logger.info("Expected Alembic head revision: %s", head_revision)
            _purge_removed_vuln_library_tasks(logger)
            ensure_audit_log_storage()
            with SessionLocal() as db:
                try:
                    bootstrap_summary = ensure_campus_auto_bootstrap(db)
                    if any(int(value or 0) > 0 for value in bootstrap_summary.values()):
                        logger.info("Auto-bootstrapped campus discovery defaults: %s", bootstrap_summary)
                except Exception as exc:  # pragma: no cover - startup bootstrap should not break app
                    db.rollback()
                    logger.warning("Campus auto bootstrap skipped: %s", exc)
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
            try:
                await close_rate_limit_client()
            except Exception:
                pass
            await device_alert_hub.stop()

    app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)
    if settings.CORS_ALLOW_ALL:
        cors_allow_origins = ["*"]
        cors_allow_origin_regex = None
        cors_allow_credentials = False
        logger.info("CORS running in development allow-all mode")
    else:
        cors_allow_origins, cors_allow_origin_regex = _build_cors_allowlist(settings.CORS_ALLOW_ORIGINS)
        cors_allow_credentials = True
        logger.info(
            "CORS allowlist mode enabled for origins=%s regex=%s",
            cors_allow_origins,
            cors_allow_origin_regex,
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_allow_origins,
        allow_origin_regex=cors_allow_origin_regex,
        allow_credentials=cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        request_id = new_request_id(request)
        started_at = time.perf_counter()
        response = None
        rate_decision = None
        rate_limited = False
        error_message = None
        try:
            if not should_skip_rate_limit(request):
                rate_decision = await check_rate_limit(request)
                if not rate_decision.allowed:
                    rate_limited = True
                    response = JSONResponse(status_code=429, content={"detail": "请求过于频繁，请稍后重试"})
                    return response

            response = await call_next(request)
            return response
        except Exception as exc:
            error_message = str(exc)
            raise
        finally:
            status_code = response.status_code if response is not None else 500
            if response is not None:
                response.headers["X-Request-ID"] = request_id
                if rate_decision is not None:
                    response.headers.update(build_rate_limit_headers(rate_decision))
            write_audit_log(
                request=request,
                request_id=request_id,
                status_code=status_code,
                duration_ms=monotonic_ms(started_at),
                rate_limited=rate_limited,
                error_message=error_message,
                payload_json={
                    "rate_limited": rate_limited,
                    "rate_limit_remaining": rate_decision.remaining if rate_decision is not None else None,
                },
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
