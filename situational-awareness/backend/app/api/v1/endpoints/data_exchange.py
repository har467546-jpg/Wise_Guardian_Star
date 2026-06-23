from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_admin_user, get_db_session
from app.db.models.user import User
from app.schemas.data_exchange import ServerImportResponse
from app.services.data_exchange_service import (
    export_dataset,
    import_servers_csv,
    server_template_csv_bytes,
)

router = APIRouter()


@router.get("/servers/template")
def download_server_csv_template(_: User = Depends(get_admin_user)) -> Response:
    return Response(
        content=server_template_csv_bytes(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="server-import-template.csv"'},
    )


@router.post("/servers/import", response_model=ServerImportResponse)
async def import_servers(
    file: UploadFile = File(...),
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_admin_user),
) -> ServerImportResponse:
    filename = str(file.filename or "").lower()
    if filename and not filename.endswith(".csv"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="仅支持 CSV 文件")
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSV 文件为空")
    try:
        raw_csv = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSV 文件必须使用 UTF-8 编码") from exc
    try:
        return import_servers_csv(db, raw_csv=raw_csv, current_user_id=current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/export/{data_type}")
def export_data(
    data_type: str,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> Response:
    try:
        filename, media_type, content = export_dataset(db, data_type=data_type, file_format=format)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
