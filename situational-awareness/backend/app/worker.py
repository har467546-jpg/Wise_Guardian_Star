from app.core.celery_app import celery_app
from app.core.logging import configure_logging
from celery.signals import worker_process_init, worker_process_shutdown
from app.services.ai.model_router_service import start_gateway_config_subscriber, stop_gateway_config_subscriber
from app.services.platform_log_service import install_platform_log_capture

configure_logging()
install_platform_log_capture(service_name="worker")


@worker_process_init.connect
def _start_gateway_subscriber(**_kwargs) -> None:  # type: ignore[no-untyped-def]
    try:
        start_gateway_config_subscriber(service_name="worker")
    except Exception:
        pass


@worker_process_shutdown.connect
def _stop_gateway_subscriber(**_kwargs) -> None:  # type: ignore[no-untyped-def]
    try:
        stop_gateway_config_subscriber()
    except Exception:
        pass

__all__ = ["celery_app"]
