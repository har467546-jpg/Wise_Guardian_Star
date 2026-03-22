import base64
import hashlib

from cryptography.fernet import Fernet

from app.core.config import settings


def _build_fernet() -> Fernet:
    key = settings.ENCRYPTION_KEY
    if key:
        return Fernet(key.encode())

    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    derived = base64.urlsafe_b64encode(digest)
    return Fernet(derived)


fernet = _build_fernet()


def encrypt_text(raw: str) -> str:
    return fernet.encrypt(raw.encode()).decode()


def decrypt_text(ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()
