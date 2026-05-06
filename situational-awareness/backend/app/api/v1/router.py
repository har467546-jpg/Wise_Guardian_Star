from fastapi import APIRouter

from app.api.v1.endpoints import (
    agent,
    assets,
    auth,
    campus,
    collection,
    dashboard,
    discovery,
    logs,
    mobile,
    monitoring,
    remediation,
    reports,
    risks,
    runner,
    settings,
    tasks,
    vuln_library,
)

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(agent.router, prefix="/agent", tags=["agent"])
api_router.include_router(discovery.router, prefix="/discovery", tags=["discovery"])
api_router.include_router(campus.router, prefix="/campus", tags=["campus"])
api_router.include_router(mobile.router, prefix="/mobile", tags=["mobile"])
api_router.include_router(monitoring.router, prefix="/monitoring", tags=["monitoring"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(collection.router, prefix="/collection", tags=["collection"])
api_router.include_router(risks.router, prefix="/risks", tags=["risks"])
api_router.include_router(remediation.router, prefix="/remediation", tags=["remediation"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(runner.router, prefix="/runner", tags=["runner"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(tasks.router, prefix="/tasks", tags=["tasks"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"])
api_router.include_router(vuln_library.router, prefix="/vuln-library", tags=["vuln-library"])
