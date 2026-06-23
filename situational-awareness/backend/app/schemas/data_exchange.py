from pydantic import BaseModel


class ServerImportIssue(BaseModel):
    row: int
    field: str | None = None
    message: str


class ServerImportResponse(BaseModel):
    total_rows: int
    created: int
    updated: int
    credential_saved: int
    skipped: int
    issues: list[ServerImportIssue] = []
