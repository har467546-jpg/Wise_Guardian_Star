from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.db.models.user import User
from app.schemas.monitoring import PlatformLiveMetricsRead
from app.services.platform_monitoring_service import platform_monitoring_service

router = APIRouter()


@router.get("/platform/live", response_model=PlatformLiveMetricsRead)
def get_platform_live_metrics(_: User = Depends(get_current_user)) -> PlatformLiveMetricsRead:
    return platform_monitoring_service.get_live_metrics()
