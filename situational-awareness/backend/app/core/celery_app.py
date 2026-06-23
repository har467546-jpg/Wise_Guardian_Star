from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery("asset_platform", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    task_track_started=True,
    worker_prefetch_multiplier=1,
    include=[
        "app.tasks.discovery_tasks",
        "app.tasks.collection_tasks",
        "app.tasks.scan_tasks",
        "app.tasks.collect_tasks",
        "app.tasks.risk_tasks",
        "app.tasks.report_tasks",
        "app.tasks.remediation_tasks",
        "app.tasks.runner_tasks",
        "app.tasks.agent_tasks",
        "app.tasks.verify_tasks",
        "app.tasks.vuln_intel_tasks",
    ],
)

celery_app.conf.task_routes = {
    "app.tasks.discovery_tasks.*": {"queue": "discovery"},
    "app.tasks.collection_tasks.*": {"queue": "collection"},
    "app.tasks.scan_tasks.*": {"queue": "discovery"},
    "app.tasks.collect_tasks.*": {"queue": "collection"},
    "app.tasks.risk_tasks.*": {"queue": "risk"},
    "app.tasks.report_tasks.*": {"queue": "report"},
    "app.tasks.remediation_tasks.*": {"queue": "collection"},
    "app.tasks.runner_tasks.*": {"queue": "collection"},
    "app.tasks.agent_tasks.*": {"queue": "collection"},
    "app.tasks.verify_tasks.*": {"queue": "risk"},
    "app.tasks.vuln_intel_tasks.*": {"queue": "risk"},
}

celery_app.conf.beat_schedule = {
    "hourly-vuln-intel-sync": {
        "task": "app.tasks.vuln_intel_tasks.sync_vuln_intel",
        "schedule": crontab(minute=0),
    }
}
