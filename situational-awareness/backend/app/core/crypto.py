import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

AES_GCM_PREFIX = "v2:aes-256-gcm:"
AES_GCM_NONCE_BYTES = 12
AES_GCM_AAD = b"asset-situational-awareness:v2:aes-256-gcm"
WEAK_SECRET_KEYS = {"", "change-me", "change-this-secret"}


def _urlsafe_b64decode_padded(value: str) -> bytes:
    normalized = value.strip().encode()
    return base64.urlsafe_b64decode(normalized + b"=" * (-len(normalized) % 4))


def _build_key_bytes() -> bytes:
    key = settings.ENCRYPTION_KEY.strip()
    if key:
        try:
            decoded = _urlsafe_b64decode_padded(key)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        try:
            decoded = bytes.fromhex(key)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass
        raw = key.encode()
        if len(raw) == 32:
            return raw
        return hashlib.sha256(raw).digest()
    return hashlib.sha256(settings.SECRET_KEY.encode()).digest()


def encryption_key_is_strong() -> bool:
    key = settings.ENCRYPTION_KEY.strip()
    if not key:
        return False
    try:
        decoded = _urlsafe_b64decode_padded(key)
        if len(decoded) == 32:
            return True
    except Exception:
        pass
    try:
        decoded = bytes.fromhex(key)
        if len(decoded) == 32:
            return True
    except ValueError:
        pass
    return len(key.encode()) == 32


def validate_production_crypto_settings() -> None:
    if str(settings.ENV or "").strip().lower() not in {"prod", "production"}:
        return
    if settings.SECRET_KEY.strip() in WEAK_SECRET_KEYS:
        raise RuntimeError("生产环境必须配置强 SECRET_KEY，不能使用默认值")
    if not encryption_key_is_strong():
        raise RuntimeError("生产环境必须配置独立的 32 字节 ENCRYPTION_KEY")


def _build_legacy_fernets() -> list[Fernet]:
    fernets: list[Fernet] = []
    key = settings.ENCRYPTION_KEY.strip()
    if key:
        try:
            fernets.append(Fernet(key.encode()))
        except Exception:
            pass
        try:
            decoded = _urlsafe_b64decode_padded(key)
            if len(decoded) == 32:
                encoded = base64.urlsafe_b64encode(decoded)
                if encoded.decode() != key:
                    fernets.append(Fernet(encoded))
        except Exception:
            pass
        try:
            decoded = bytes.fromhex(key)
            if len(decoded) == 32:
                fernets.append(Fernet(base64.urlsafe_b64encode(decoded)))
        except ValueError:
            pass
        raw = key.encode()
        if len(raw) == 32:
            fernets.append(Fernet(base64.urlsafe_b64encode(raw)))

    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    derived = base64.urlsafe_b64encode(digest)
    fernets.append(Fernet(derived))
    return fernets


def _build_aesgcm() -> AESGCM:
    return AESGCM(_build_key_bytes())


def encrypt_text(raw: str) -> str:
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    ciphertext = _build_aesgcm().encrypt(nonce, raw.encode(), AES_GCM_AAD)
    payload = base64.urlsafe_b64encode(nonce + ciphertext).decode().rstrip("=")
    return f"{AES_GCM_PREFIX}{payload}"


def decrypt_text(ciphertext: str) -> str:
    if ciphertext.startswith(AES_GCM_PREFIX):
        payload = _urlsafe_b64decode_padded(ciphertext.removeprefix(AES_GCM_PREFIX))
        nonce = payload[:AES_GCM_NONCE_BYTES]
        encrypted = payload[AES_GCM_NONCE_BYTES:]
        return _build_aesgcm().decrypt(nonce, encrypted, AES_GCM_AAD).decode()
    last_error: Exception | None = None
    for fernet in _build_legacy_fernets():
        try:
            return fernet.decrypt(ciphertext.encode()).decode()
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise ValueError("No legacy Fernet keys available")
