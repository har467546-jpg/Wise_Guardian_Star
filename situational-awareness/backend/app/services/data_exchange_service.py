from __future__ import annotations

import csv
import io
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.crypto import encrypt_text
from app.db.models.asset import Asset, AssetTag
from app.db.models.credential import AssetCredentialBinding, SSHCredential
from app.db.models.enums import AssetStatus, CredentialAuthType, FindingStatus
from app.db.models.report import AIReport
from app.db.models.risk_finding import RiskFinding
from app.db.models.tag import Tag
from app.db.models.audit_log_entry import AuditLogEntry
from app.schemas.data_exchange import ServerImportIssue, ServerImportResponse

SERVER_IMPORT_HEADERS = [
    "name",
    "hostname",
    "ip",
    "port",
    "os",
    "username",
    "password",
    "tags",
    "description",
]

SERVER_CSV_TEMPLATE = """name,hostname,ip,port,os,username,password,tags,description
Web-Server-01,web01,192.168.1.10,22,Ubuntu 22.04,root,password123,web;prod,主 Web 服务器
DB-Server-01,db01,192.168.1.20,22,CentOS 8,root,password456,db;prod,MySQL 数据库服务器
"""

EXPORT_DATA_TYPES = {"servers", "alerts", "audit_logs", "reports"}
EXPORT_FORMATS = {"csv", "json"}


def server_template_csv_bytes() -> bytes:
    return _with_utf8_bom(SERVER_CSV_TEMPLATE)


def import_servers_csv(db: Session, *, raw_csv: str, current_user_id: str | None = None) -> ServerImportResponse:
    reader = csv.DictReader(io.StringIO(raw_csv.lstrip("\ufeff")))
    if not reader.fieldnames:
        raise ValueError("CSV 文件为空")
    normalized_headers = [str(item or "").strip() for item in reader.fieldnames]
    missing_headers = [header for header in SERVER_IMPORT_HEADERS if header not in normalized_headers]
    if missing_headers:
        raise ValueError(f"CSV 缺少字段：{', '.join(missing_headers)}")

    total_rows = 0
    created = 0
    updated = 0
    credential_saved = 0
    skipped = 0
    issues: list[ServerImportIssue] = []
    seen_names: set[str] = set()

    for row_index, row in enumerate(reader, start=2):
        total_rows += 1
        normalized = {header: str(row.get(header) or "").strip() for header in SERVER_IMPORT_HEADERS}
        name = normalized["name"]
        hostname = normalized["hostname"]
        ip = normalized["ip"]
        if not name:
            issues.append(ServerImportIssue(row=row_index, field="name", message="服务器名称不能为空"))
            skipped += 1
            continue
        if name in seen_names:
            issues.append(ServerImportIssue(row=row_index, field="name", message="CSV 内服务器名称重复"))
            skipped += 1
            continue
        seen_names.add(name)
        if not hostname:
            issues.append(ServerImportIssue(row=row_index, field="hostname", message="主机名不能为空"))
            skipped += 1
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            issues.append(ServerImportIssue(row=row_index, field="ip", message="IP 地址格式无效"))
            skipped += 1
            continue

        port = _parse_ssh_port(normalized["port"], row_index=row_index, issues=issues)
        if port is None:
            skipped += 1
            continue

        existing_by_name = _find_imported_asset_by_name(db, name)
        existing_by_ip = db.scalar(select(Asset).where(Asset.ip == ip))
        if existing_by_name is not None and existing_by_ip is not None and existing_by_name.id != existing_by_ip.id:
            issues.append(ServerImportIssue(row=row_index, field="ip", message="IP 已属于其他资产"))
            skipped += 1
            continue
        asset = existing_by_name or existing_by_ip
        now = datetime.now(timezone.utc)
        import_payload = {
            "name": name,
            "description": normalized["description"],
            "ssh_port": port,
            "tags": _split_tags(normalized["tags"]),
            "imported_at": now.isoformat(),
        }
        if asset is None:
            asset = Asset(
                id=str(uuid4()),
                ip=ip,
                hostname=hostname or name,
                os_name=normalized["os"] or None,
                status=AssetStatus.UNKNOWN,
                identity_source="csv_import",
                device_assessment_json={"import": import_payload},
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(asset)
            db.flush()
            created += 1
        else:
            assessment = dict(asset.device_assessment_json) if isinstance(asset.device_assessment_json, dict) else {}
            assessment["import"] = {**dict(assessment.get("import") or {}), **import_payload}
            asset.hostname = hostname or asset.hostname or name
            asset.os_name = normalized["os"] or asset.os_name
            asset.identity_source = asset.identity_source or "csv_import"
            asset.device_assessment_json = assessment
            asset.last_seen_at = now
            updated += 1

        _replace_asset_tag_names(db, asset=asset, tag_names=import_payload["tags"])
        if normalized["username"] or normalized["password"]:
            if not normalized["username"] or not normalized["password"]:
                issues.append(ServerImportIssue(row=row_index, field="username", message="SSH 用户名和密码必须同时填写"))
            else:
                _upsert_password_credential(
                    db,
                    asset=asset,
                    username=normalized["username"],
                    password=normalized["password"],
                    current_user_id=current_user_id,
                )
                credential_saved += 1

    db.commit()
    return ServerImportResponse(
        total_rows=total_rows,
        created=created,
        updated=updated,
        credential_saved=credential_saved,
        skipped=skipped,
        issues=issues[:200],
    )


def export_dataset(db: Session, *, data_type: str, file_format: str) -> tuple[str, str, bytes]:
    normalized_type = data_type.strip().lower()
    normalized_format = file_format.strip().lower()
    if normalized_type not in EXPORT_DATA_TYPES:
        raise ValueError("不支持的数据类型")
    if normalized_format not in EXPORT_FORMATS:
        raise ValueError("不支持的导出格式")

    rows = _export_rows(db, normalized_type)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    filename = f"{normalized_type}-{timestamp}.{normalized_format}"
    if normalized_format == "json":
        return filename, "application/json; charset=utf-8", json.dumps(rows, ensure_ascii=False, default=str, indent=2).encode("utf-8")
    return filename, "text/csv; charset=utf-8", _rows_to_csv_bytes(rows)


def _export_rows(db: Session, data_type: str) -> list[dict[str, Any]]:
    if data_type == "servers":
        return _export_server_rows(db)
    if data_type == "alerts":
        return _export_alert_rows(db)
    if data_type == "audit_logs":
        return _export_audit_log_rows(db)
    if data_type == "reports":
        return _export_report_rows(db)
    raise ValueError("不支持的数据类型")


def _export_server_rows(db: Session) -> list[dict[str, Any]]:
    assets = db.scalars(select(Asset).options(joinedload(Asset.tags).joinedload(AssetTag.tag)).order_by(Asset.last_seen_at.desc())).unique().all()
    rows: list[dict[str, Any]] = []
    for asset in assets:
        import_payload = dict((asset.device_assessment_json or {}).get("import") or {}) if isinstance(asset.device_assessment_json, dict) else {}
        tag_names = [item.tag.name for item in asset.tags if item.tag is not None]
        rows.append(
            {
                "服务器名称": import_payload.get("name") or asset.hostname or str(asset.ip),
                "主机名": asset.hostname or "",
                "IP 地址": str(asset.ip),
                "SSH 端口": import_payload.get("ssh_port") or 22,
                "操作系统": asset.os_name or "",
                "SSH 用户名": _credential_username(db, asset.id) or "",
                "标签": ";".join(tag_names or import_payload.get("tags") or []),
                "描述": import_payload.get("description") or "",
                "状态": asset.status.value if hasattr(asset.status, "value") else str(asset.status),
                "首次发现时间": _format_dt(asset.first_seen_at),
                "最近发现时间": _format_dt(asset.last_seen_at),
            }
        )
    return rows


def _export_alert_rows(db: Session) -> list[dict[str, Any]]:
    findings = db.scalars(
        select(RiskFinding).options(joinedload(RiskFinding.asset)).where(RiskFinding.status == FindingStatus.OPEN).order_by(RiskFinding.detected_at.desc())
    ).all()
    return [
        {
            "告警ID": finding.id,
            "资产ID": finding.asset_id,
            "资产IP": str(finding.asset.ip) if finding.asset is not None else "",
            "资产主机名": finding.asset.hostname if finding.asset is not None else "",
            "严重级别": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "状态": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
            "标题": finding.title,
            "描述": finding.description,
            "检测时间": _format_dt(finding.detected_at),
        }
        for finding in findings
    ]


def _export_audit_log_rows(db: Session) -> list[dict[str, Any]]:
    entries = db.scalars(select(AuditLogEntry).order_by(AuditLogEntry.created_at.desc()).limit(5000)).all()
    return [
        {
            "审计ID": item.id,
            "请求ID": item.request_id,
            "用户ID": item.actor_user_id or "",
            "角色": item.actor_role or "",
            "客户端IP": item.client_ip or "",
            "方法": item.method,
            "路径": item.path,
            "动作": item.action,
            "资源类型": item.resource_type or "",
            "资源ID": item.resource_id or "",
            "状态码": item.status_code,
            "结果": item.outcome,
            "耗时ms": item.duration_ms,
            "错误": item.error_message or "",
            "创建时间": _format_dt(item.created_at),
        }
        for item in entries
    ]


def _export_report_rows(db: Session) -> list[dict[str, Any]]:
    reports = db.scalars(select(AIReport).order_by(AIReport.created_at.desc()).limit(5000)).all()
    return [
        {
            "报表ID": item.id,
            "范围类型": item.scope.value if hasattr(item.scope, "value") else str(item.scope),
            "范围ID": item.scope_id,
            "摘要": item.summary_md,
            "风险概览": json.dumps(item.risk_overview_json or {}, ensure_ascii=False, default=str),
            "分析数据": json.dumps(item.analysis_json or {}, ensure_ascii=False, default=str),
            "创建时间": _format_dt(item.created_at),
        }
        for item in reports
    ]


def _rows_to_csv_bytes(rows: list[dict[str, Any]]) -> bytes:
    output = io.StringIO()
    if not rows:
        writer = csv.writer(output)
        writer.writerow(["暂无数据"])
    else:
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return _with_utf8_bom(output.getvalue())


def _with_utf8_bom(content: str) -> bytes:
    return ("\ufeff" + content).encode("utf-8")


def _parse_ssh_port(raw: str, *, row_index: int, issues: list[ServerImportIssue]) -> int | None:
    if not raw:
        return 22
    try:
        port = int(raw)
    except ValueError:
        issues.append(ServerImportIssue(row=row_index, field="port", message="SSH 端口必须是数字"))
        return None
    if port < 1 or port > 65535:
        issues.append(ServerImportIssue(row=row_index, field="port", message="SSH 端口范围必须为 1-65535"))
        return None
    return port


def _split_tags(raw: str) -> list[str]:
    result: list[str] = []
    for item in raw.split(";"):
        name = item.strip()
        if name and name not in result:
            result.append(name[:64])
    return result


def _find_imported_asset_by_name(db: Session, name: str) -> Asset | None:
    assets = db.scalars(select(Asset).where(Asset.device_assessment_json["import"]["name"].astext == name)).all()
    return assets[0] if assets else None


def _replace_asset_tag_names(db: Session, *, asset: Asset, tag_names: list[str]) -> None:
    db.query(AssetTag).filter(AssetTag.asset_id == asset.id).delete(synchronize_session=False)
    for tag_name in tag_names:
        tag = db.scalar(select(Tag).where(Tag.name == tag_name))
        if tag is None:
            tag = Tag(name=tag_name)
            db.add(tag)
            db.flush()
        db.add(AssetTag(asset_id=asset.id, tag_id=tag.id))


def _upsert_password_credential(db: Session, *, asset: Asset, username: str, password: str, current_user_id: str | None) -> None:
    credential = db.scalar(select(SSHCredential).where(SSHCredential.name == f"manual-asset-{asset.id}"))
    if credential is None:
        credential = SSHCredential(
            name=f"manual-asset-{asset.id}",
            username=username,
            auth_type=CredentialAuthType.PASSWORD,
            created_by=current_user_id,
        )
        db.add(credential)
        db.flush()
    credential.username = username
    credential.auth_type = CredentialAuthType.PASSWORD
    credential.secret_ciphertext = encrypt_text(password)
    credential.key_ciphertext = None
    credential.admin_authorized = False
    binding = db.scalar(
        select(AssetCredentialBinding).where(
            AssetCredentialBinding.asset_id == asset.id,
            AssetCredentialBinding.credential_id == credential.id,
        )
    )
    if binding is None:
        db.add(AssetCredentialBinding(asset_id=asset.id, credential_id=credential.id, priority=10))


def _credential_username(db: Session, asset_id: str) -> str | None:
    credential = db.scalar(select(SSHCredential).where(SSHCredential.name == f"manual-asset-{asset_id}"))
    return credential.username if credential else None


def _format_dt(value: datetime | None) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if value else ""
