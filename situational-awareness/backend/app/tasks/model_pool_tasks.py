from __future__ import annotations

from celery import Task

from app.core.celery_app import celery_app
from app.services.ai.model_router_service import aggregate_gateway_metrics, check_cooldown_channels, probe_gateway_channel
from app.services.ai.model_pool_service import probe_model_pool_node, probe_unhealthy_model_pool_nodes


@celery_app.task(bind=True, name="app.tasks.model_pool_tasks.probe_model_pool_node")
def probe_model_pool_node_task(self: Task, node_id: str) -> dict[str, object]:
    record = probe_model_pool_node(node_id)
    if record is None:
        return {"node_id": node_id, "skipped": True}
    return {
        "node_id": record.node_id,
        "success": record.success,
        "latency_ms": record.latency_ms,
        "error": record.error,
        "status_code": record.status_code,
        "purpose": record.purpose,
    }


@celery_app.task(bind=True, name="app.tasks.model_pool_tasks.probe_unhealthy_model_pool_nodes")
def probe_unhealthy_model_pool_nodes_task(self: Task) -> dict[str, object]:
    return probe_unhealthy_model_pool_nodes()


@celery_app.task(bind=True, name="app.tasks.model_pool_tasks.check_cooldown_channels")
def check_cooldown_channels_task(self: Task) -> dict[str, object]:
    return check_cooldown_channels()


@celery_app.task(bind=True, name="app.tasks.model_pool_tasks.aggregate_gateway_metrics")
def aggregate_gateway_metrics_task(self: Task) -> dict[str, object]:
    return aggregate_gateway_metrics()


@celery_app.task(bind=True, name="app.tasks.model_pool_tasks.probe_gateway_channel")
def probe_gateway_channel_task(self: Task, channel_id: int | str) -> dict[str, object]:
    record = probe_gateway_channel(channel_id, include_disabled=True)
    if record is None:
        return {"channel_id": channel_id, "skipped": True}
    return {
        "channel_id": record.channel_id,
        "success": record.success,
        "latency_ms": record.latency_ms,
        "error": record.error,
        "status_code": record.status_code,
        "purpose": record.purpose,
    }
