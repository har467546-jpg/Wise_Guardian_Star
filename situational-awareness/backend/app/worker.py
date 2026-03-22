from app.core.celery_app import celery_app
from app.core.logging import configure_logging
from app.services.platform_log_service import install_platform_log_capture

configure_logging()
install_platform_log_capture(service_name="worker")

__all__ = ["celery_app"]
