from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass


_IP_ADDR_LINE_RE = re.compile(r"^\d+:\s+(?P<name>\S+)\s+inet\s+(?P<cidr>\d+\.\d+\.\d+\.\d+/\d+)\b")


@dataclass(frozen=True, slots=True)
class LocalIPv4Interface:
    name: str
    interface: ipaddress.IPv4Interface

    @property
    def ip(self) -> str:
        return str(self.interface.ip)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.interface.network


def normalize_cidr(raw: str) -> str:
    return str(ipaddress.ip_network(raw, strict=False))


def list_local_ipv4_interfaces() -> list[LocalIPv4Interface]:
    try:
        process = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "up"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return []
    if process.returncode != 0:
        return []

    interfaces: list[LocalIPv4Interface] = []
    for raw_line in process.stdout.splitlines():
        match = _IP_ADDR_LINE_RE.match(raw_line.strip())
        if match is None:
            continue
        name = match.group("name").strip()
        cidr = match.group("cidr").strip()
        if not name or name == "lo":
            continue
        try:
            interface = ipaddress.IPv4Interface(cidr)
        except ValueError:
            continue
        if interface.ip.is_loopback:
            continue
        interfaces.append(LocalIPv4Interface(name=name, interface=interface))
    return interfaces


def list_local_ipv4_addresses() -> list[str]:
    seen: set[str] = set()
    values: list[str] = []
    for entry in list_local_ipv4_interfaces():
        ip = entry.ip
        if ip in seen:
            continue
        seen.add(ip)
        values.append(ip)
    return values


def find_local_ipv4_interface_for_network(
    network: ipaddress.IPv4Network | str,
) -> LocalIPv4Interface | None:
    target = ipaddress.ip_network(network, strict=False) if isinstance(network, str) else network
    if not isinstance(target, ipaddress.IPv4Network):
        return None

    candidates = [
        entry
        for entry in list_local_ipv4_interfaces()
        if target.subnet_of(entry.network)
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (item.network.prefixlen, item.name), reverse=True)[0]
