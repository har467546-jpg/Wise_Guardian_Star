from __future__ import annotations

from functools import lru_cache
import re

from packaging.version import InvalidVersion, Version


_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)*(?:p\d+)?", re.IGNORECASE)
_DEBIAN_EPOCH_RE = re.compile(r"^(?P<epoch>\d+):")


def normalize_version_token(raw: str | None) -> str | None:
    if not raw:
        return None

    token = str(raw).strip()
    if not token:
        return None

    token = re.sub(r"^\d+:", "", token)
    match = _VERSION_TOKEN_RE.search(token)
    if match is None:
        return None

    normalized = match.group(0)
    patch_match = re.search(r"^(?P<base>\d+(?:\.\d+)*)p(?P<patch>\d+)$", normalized, re.IGNORECASE)
    if patch_match:
        return f"{patch_match.group('base')}.post{patch_match.group('patch')}"
    return normalized


def normalize_linux_distro(name: str | None, version_id: str | None) -> tuple[str | None, str | None]:
    distro_name = str(name or "").strip().lower()
    distro_version = str(version_id or "").strip()
    if not distro_name or not distro_version:
        return None, None

    if distro_name == "ubuntu" or distro_name.startswith("ubuntu "):
        release_match = re.search(r"\d+\.\d+", distro_version)
        return "ubuntu", release_match.group(0) if release_match else None

    if distro_name == "debian" or distro_name.startswith("debian"):
        major_match = re.search(r"\d+", distro_version)
        return "debian", major_match.group(0) if major_match else None

    return None, None


@lru_cache(maxsize=1)
def _load_debian_version_class():
    try:
        from debian.debian_support import Version as DebianVersion  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised in runtime environments only
        raise RuntimeError("python-debian 未安装，无法比较 Debian 软件包版本") from exc
    return DebianVersion


def compare_debian_package_versions(left: str | None, right: str | None) -> int:
    left_value = str(left or "").strip()
    right_value = str(right or "").strip()
    if not left_value or not right_value:
        raise ValueError("Debian 软件包版本比较需要同时提供左右版本号")

    left_epoch = _DEBIAN_EPOCH_RE.match(left_value)
    right_epoch = _DEBIAN_EPOCH_RE.match(right_value)
    if left_epoch and not right_epoch:
        right_value = f"{left_epoch.group('epoch')}:{right_value}"

    version_class = _load_debian_version_class()
    left_version = version_class(left_value)
    right_version = version_class(right_value)
    if left_version < right_version:
        return -1
    if left_version > right_version:
        return 1
    return 0


def is_version_less_than(left: str | None, right: str | None) -> bool:
    normalized_left = normalize_version_token(left)
    normalized_right = normalize_version_token(right)
    if not normalized_left or not normalized_right:
        return False
    try:
        return Version(normalized_left) < Version(normalized_right)
    except InvalidVersion:
        return False
