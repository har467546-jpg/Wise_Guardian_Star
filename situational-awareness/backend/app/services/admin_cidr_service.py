from __future__ import annotations

import ipaddress
from typing import Any

from app.core.config import settings


def parse_admin_cidrs(value: Any) -> list[str]:
    items: list[str] = []
    seen: set[str] = set()
    if isinstance(value, (list, tuple, set)):
        raw_items = [str(item or "").strip() for item in value]
    else:
        raw_items = [item.strip() for item in str(value or "").split(",")]
    for raw in raw_items:
        if not raw:
            continue
        network = ipaddress.ip_network(raw, strict=False)
        normalized = str(network)
        if normalized in seen:
            continue
        seen.add(normalized)
        items.append(normalized)
    return items


def get_admin_cidrs() -> list[str]:
    return parse_admin_cidrs(getattr(settings, "SECURITY_ADMIN_CIDRS", ""))


def has_admin_cidrs() -> bool:
    return bool(get_admin_cidrs())
