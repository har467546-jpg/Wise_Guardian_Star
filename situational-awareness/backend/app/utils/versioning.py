from __future__ import annotations

from functools import lru_cache
import re

from packaging.version import InvalidVersion, Version


_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)*(?:p\d+)?", re.IGNORECASE)
_DEBIAN_EPOCH_RE = re.compile(r"^(?P<epoch>\d+):")
_RPM_NUMERIC_RE = re.compile(r"\d+")


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


def normalize_package_manager(name: str | None) -> str | None:
    normalized = str(name or "").strip().lower()
    if not normalized:
        return None
    aliases = {
        "apt": "dpkg",
        "apt-get": "dpkg",
        "deb": "dpkg",
        "dpkg": "dpkg",
        "dnf": "rpm",
        "yum": "rpm",
        "rpm": "rpm",
        "apk": "apk",
    }
    return aliases.get(normalized, normalized)


def normalize_linux_distro_key(name: str | None) -> str | None:
    normalized = str(name or "").strip().lower()
    if not normalized:
        return None
    aliases = {
        "ubuntu": "ubuntu",
        "debian": "debian",
        "rhel": "rhel",
        "redhat": "rhel",
        "red hat": "rhel",
        "red hat enterprise linux": "rhel",
        "red hat enterprise linux server": "rhel",
        "red hat enterprise linux workstation": "rhel",
        "centos": "centos",
        "centos linux": "centos",
        "centos stream": "centos",
        "rocky": "rocky",
        "rocky linux": "rocky",
        "alma": "almalinux",
        "alma linux": "almalinux",
        "almalinux": "almalinux",
        "alma linux os": "almalinux",
    }
    if normalized in aliases:
        return aliases[normalized]
    if normalized.startswith("ubuntu "):
        return "ubuntu"
    if normalized.startswith("debian"):
        return "debian"
    if normalized.startswith("rocky"):
        return "rocky"
    if normalized.startswith("almalinux") or normalized.startswith("alma linux"):
        return "almalinux"
    if normalized.startswith("centos"):
        return "centos"
    if normalized.startswith("red hat"):
        return "rhel"
    return normalized


def normalize_linux_distro(name: str | None, version_id: str | None) -> tuple[str | None, str | None]:
    distro_name = normalize_linux_distro_key(name)
    distro_version = str(version_id or "").strip()
    if not distro_name:
        return None, None
    if not distro_version:
        return distro_name, None

    if distro_name == "ubuntu":
        release_match = re.search(r"\d+\.\d+", distro_version)
        return "ubuntu", release_match.group(0) if release_match else None

    if distro_name == "debian":
        major_match = re.search(r"\d+", distro_version)
        return "debian", major_match.group(0) if major_match else None

    if distro_name in {"rhel", "centos", "rocky", "almalinux"}:
        major_match = re.search(r"\d+", distro_version)
        return distro_name, major_match.group(0) if major_match else None

    return distro_name, None


def normalize_linux_distro_text(raw: str | None) -> tuple[str | None, str | None]:
    text = str(raw or "").strip()
    if not text:
        return None, None
    lowered = text.lower()
    if "ubuntu" in lowered:
        return normalize_linux_distro("ubuntu", text)
    if "debian" in lowered:
        return normalize_linux_distro("debian", text)
    if "rocky" in lowered:
        return normalize_linux_distro("rocky", text)
    if "almalinux" in lowered or "alma linux" in lowered:
        return normalize_linux_distro("almalinux", text)
    if "centos" in lowered:
        return normalize_linux_distro("centos", text)
    if "red hat" in lowered or "rhel" in lowered:
        return normalize_linux_distro("rhel", text)
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


def compare_rpm_package_versions(left: str | None, right: str | None) -> int:
    left_epoch, left_version, left_release = _split_rpm_evr(left)
    right_epoch, right_version, right_release = _split_rpm_evr(right)

    if left_epoch < right_epoch:
        return -1
    if left_epoch > right_epoch:
        return 1

    version_result = _rpmvercmp(left_version, right_version)
    if version_result != 0:
        return version_result
    return _rpmvercmp(left_release, right_release)


def is_version_less_than(left: str | None, right: str | None) -> bool:
    normalized_left = normalize_version_token(left)
    normalized_right = normalize_version_token(right)
    if not normalized_left or not normalized_right:
        return False
    try:
        return Version(normalized_left) < Version(normalized_right)
    except InvalidVersion:
        return False


def _split_rpm_evr(raw: str | None) -> tuple[int, str, str]:
    value = str(raw or "").strip()
    if not value:
        raise ValueError("RPM 软件包版本比较需要同时提供左右版本号")

    epoch = 0
    if ":" in value:
        prefix, suffix = value.split(":", 1)
        if prefix.isdigit():
            epoch = int(prefix)
            value = suffix

    version = value
    release = ""
    if "-" in value:
        version, release = value.rsplit("-", 1)
    return epoch, version, release


def _rpmvercmp(left: str, right: str) -> int:
    left_value = left or ""
    right_value = right or ""
    left_index = 0
    right_index = 0

    while True:
        left_index, right_index, tilde_result = _consume_rpm_tilde(left_value, right_value, left_index, right_index)
        if tilde_result is not None:
            return tilde_result

        left_index = _skip_rpm_separators(left_value, left_index)
        right_index = _skip_rpm_separators(right_value, right_index)

        if left_index >= len(left_value) and right_index >= len(right_value):
            return 0
        if left_index >= len(left_value):
            return -1
        if right_index >= len(right_value):
            return 1

        left_is_digit = left_value[left_index].isdigit()
        right_is_digit = right_value[right_index].isdigit()
        if left_is_digit != right_is_digit:
            return 1 if left_is_digit else -1

        if left_is_digit:
            left_index, right_index, result = _compare_rpm_numeric_segment(left_value, right_value, left_index, right_index)
        else:
            left_index, right_index, result = _compare_rpm_alpha_segment(left_value, right_value, left_index, right_index)
        if result != 0:
            return result


def _consume_rpm_tilde(left: str, right: str, left_index: int, right_index: int) -> tuple[int, int, int | None]:
    left_has_tilde = left_index < len(left) and left[left_index] == "~"
    right_has_tilde = right_index < len(right) and right[right_index] == "~"
    if not left_has_tilde and not right_has_tilde:
        return left_index, right_index, None
    if left_has_tilde and not right_has_tilde:
        return left_index, right_index, -1
    if right_has_tilde and not left_has_tilde:
        return left_index, right_index, 1
    return left_index + 1, right_index + 1, None


def _skip_rpm_separators(value: str, index: int) -> int:
    while index < len(value) and not value[index].isalnum() and value[index] != "~":
        index += 1
    return index


def _compare_rpm_numeric_segment(left: str, right: str, left_index: int, right_index: int) -> tuple[int, int, int]:
    left_match = _RPM_NUMERIC_RE.match(left, left_index)
    right_match = _RPM_NUMERIC_RE.match(right, right_index)
    if left_match is None or right_match is None:
        return left_index, right_index, 0

    left_raw = left_match.group(0)
    right_raw = right_match.group(0)
    left_normalized = left_raw.lstrip("0") or "0"
    right_normalized = right_raw.lstrip("0") or "0"

    if len(left_normalized) < len(right_normalized):
        return left_match.end(), right_match.end(), -1
    if len(left_normalized) > len(right_normalized):
        return left_match.end(), right_match.end(), 1
    if left_normalized < right_normalized:
        return left_match.end(), right_match.end(), -1
    if left_normalized > right_normalized:
        return left_match.end(), right_match.end(), 1
    return left_match.end(), right_match.end(), 0


def _compare_rpm_alpha_segment(left: str, right: str, left_index: int, right_index: int) -> tuple[int, int, int]:
    left_end = left_index
    right_end = right_index
    while left_end < len(left) and left[left_end].isalpha():
        left_end += 1
    while right_end < len(right) and right[right_end].isalpha():
        right_end += 1

    left_value = left[left_index:left_end]
    right_value = right[right_index:right_end]
    if left_value < right_value:
        return left_end, right_end, -1
    if left_value > right_value:
        return left_end, right_end, 1
    return left_end, right_end, 0
