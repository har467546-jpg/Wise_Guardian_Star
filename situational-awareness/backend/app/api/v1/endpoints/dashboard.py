from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.db.models.user import User
from app.schemas.dashboard import DashboardOverviewRead
from app.services.dashboard_overview_service import build_dashboard_overview

router = APIRouter()


@router.get("/overview", response_model=DashboardOverviewRead)
def get_dashboard_overview(
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> DashboardOverviewRead:
    return build_dashboard_overview(db)
