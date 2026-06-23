from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.orm import Session

from app.core.crypto import AES_GCM_PREFIX, decrypt_text, encrypt_text
from app.db.models.campus_data_source import CampusDataSource
from app.db.models.credential import SSHCredential


@dataclass(frozen=True, slots=True)
class SecretCipherMigrationResult:
    scanned: int
    migrated: int
    failed: int


def migrate_legacy_secret_ciphertexts(db: Session, *, batch_size: int = 200) -> SecretCipherMigrationResult:
    scanned = 0
    migrated = 0
    failed = 0
    normalized_batch_size = max(1, int(batch_size or 200))

    credential_stmt = (
        select(SSHCredential)
        .where(
            or_(
                _legacy_ciphertext_filter(SSHCredential.secret_ciphertext),
                _legacy_ciphertext_filter(SSHCredential.key_ciphertext),
                _legacy_ciphertext_filter(SSHCredential.sudo_secret_ciphertext),
            )
        )
        .limit(normalized_batch_size)
    )
    for credential in db.scalars(credential_stmt).all():
        for field_name in ("secret_ciphertext", "key_ciphertext", "sudo_secret_ciphertext"):
            if not getattr(credential, field_name, None):
                continue
            scanned += 1
            changed, error = _migrate_field(credential, field_name)
            migrated += int(changed)
            failed += int(error)

    source_stmt = (
        select(CampusDataSource)
        .where(_legacy_ciphertext_filter(CampusDataSource.secret_ciphertext))
        .limit(normalized_batch_size)
    )
    for source in db.scalars(source_stmt).all():
        if not source.secret_ciphertext:
            continue
        scanned += 1
        changed, error = _migrate_field(source, "secret_ciphertext")
        migrated += int(changed)
        failed += int(error)

    if migrated:
        db.commit()
    else:
        db.rollback()
    return SecretCipherMigrationResult(scanned=scanned, migrated=migrated, failed=failed)


def _migrate_field(model: object, field_name: str) -> tuple[bool, bool]:
    current = getattr(model, field_name, None)
    if not current or str(current).startswith(AES_GCM_PREFIX):
        return False, False
    try:
        plaintext = decrypt_text(str(current))
        setattr(model, field_name, encrypt_text(plaintext))
        return True, False
    except Exception:
        return False, True


def _legacy_ciphertext_filter(column: ColumnElement[str | None]) -> ColumnElement[bool]:
    return column.is_not(None) & (column != "") & column.not_like(f"{AES_GCM_PREFIX}%")
