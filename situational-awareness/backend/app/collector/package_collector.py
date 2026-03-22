from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PackageCollectionPlan:
    manager: str
    detect_command: str
    collect_command: str


PACKAGE_COLLECTION_PLANS: tuple[PackageCollectionPlan, ...] = (
    PackageCollectionPlan(
        manager="dpkg",
        detect_command="command -v dpkg-query >/dev/null 2>&1",
        collect_command="dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'",
    ),
    PackageCollectionPlan(
        manager="rpm",
        detect_command="command -v rpm >/dev/null 2>&1",
        collect_command="rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'",
    ),
    PackageCollectionPlan(
        manager="apk",
        detect_command="command -v apk >/dev/null 2>&1",
        collect_command="apk info -v",
    ),
)

APK_PACKAGE_RE = re.compile(r"^(?P<name>.+)-(?P<version>\d[^\\s]*)$")


def parse_packages(manager: str, raw: str | None) -> list[dict[str, str | None]]:
    if not raw:
        return []
    parser = {
        "dpkg": _parse_delimited_packages,
        "rpm": _parse_delimited_packages,
        "apk": _parse_apk_packages,
    }.get(manager)
    if parser is None:
        return []
    return parser(raw, manager)


def _parse_delimited_packages(raw: str, manager: str) -> list[dict[str, str | None]]:
    packages: list[dict[str, str | None]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        name = parts[0] if parts else None
        version = parts[1] if len(parts) > 1 else None
        arch = parts[2] if len(parts) > 2 else None
        if not name:
            continue
        packages.append(
            {
                "name": name,
                "version": version,
                "manager": manager,
                "arch": arch,
            }
        )
    return packages


def _parse_apk_packages(raw: str, manager: str) -> list[dict[str, str | None]]:
    packages: list[dict[str, str | None]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        match = APK_PACKAGE_RE.match(line)
        if match:
            name = match.group("name")
            version = match.group("version")
        else:
            name = line
            version = None
        packages.append(
            {
                "name": name,
                "version": version,
                "manager": manager,
                "arch": None,
            }
        )
    return packages
