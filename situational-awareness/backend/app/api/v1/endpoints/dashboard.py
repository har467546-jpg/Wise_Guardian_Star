from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.api.v1.endpoints.mobile import get_mobile_overview
from app.db.models.user import User
from app.schemas.mobile import MobileOverviewRead

router = APIRouter()


@router.get("/overview", response_model=MobileOverviewRead)
def get_dashboard_overview(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> MobileOverviewRead:
    return get_mobile_overview(db=db, _=user)
