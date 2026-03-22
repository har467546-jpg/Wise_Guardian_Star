import ipaddress
import socket
import subprocess
from dataclasses import dataclass
from typing import Any

from app.services.discovery.fingerprint import identify_service

COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 27017]


@dataclass(slots=True)
class HostResult:
    ip: str
    hostname: str | None
    ports: list[dict[str, Any]]


class NmapScanner:
    def __init__(self, timeout: float = 0.5) -> None:
        self.timeout = timeout

    def discover(self, cidr: str) -> list[HostResult]:
        # Prefer nmap if available; fallback to socket probing.
        if self._has_nmap():
            parsed = self._run_nmap(cidr)
            if parsed:
                return parsed
        return self._fallback_scan(cidr)

    def _has_nmap(self) -> bool:
        return subprocess.call(["sh", "-c", "command -v nmap >/dev/null 2>&1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

    def _run_nmap(self, cidr: str) -> list[HostResult]:
        try:
            cmd = ["nmap", "-n", "-sV", "-Pn", "-p", ",".join(str(p) for p in COMMON_PORTS), cidr, "-oG", "-"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
            return self._parse_nmap_grepable(proc.stdout)
        except Exception:
            return []

    def _parse_nmap_grepable(self, output: str) -> list[HostResult]:
        results: dict[str, HostResult] = {}
        for line in output.splitlines():
            if not line.startswith("Host:"):
                continue
            parts = line.split("\t")
            head = parts[0].split()
            if len(head) < 2:
                continue
            ip = head[1]
            if "Ports:" not in line:
                continue
            ports_field = line.split("Ports:", 1)[1].strip()
            ports_data: list[dict[str, Any]] = []
            for chunk in ports_field.split(","):
                seg = chunk.strip().split("/")
                if len(seg) < 5:
                    continue
                try:
                    port = int(seg[0])
                except ValueError:
                    continue
                state = seg[1]
                service = seg[4] if seg[4] else "unknown"
                service_version = seg[6].strip() if len(seg) > 6 and seg[6].strip() else None
                ports_data.append(
                    {
                        "port": port,
                        "protocol": "tcp",
                        "state": state,
                        "service_name": service,
                        "service_version": service_version,
                    }
                )
            if ports_data:
                results[ip] = HostResult(ip=ip, hostname=None, ports=ports_data)
        return list(results.values())

    def _fallback_scan(self, cidr: str) -> list[HostResult]:
        net = ipaddress.ip_network(cidr, strict=False)
        results: list[HostResult] = []

        for host in net.hosts():
            ip = str(host)
            open_ports: list[dict[str, Any]] = []
            for port in COMMON_PORTS:
                if self._is_port_open(ip, port):
                    fp = identify_service(port)
                    open_ports.append(
                        {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service_name": fp.service,
                            "service_version": fp.version,
                        }
                    )
            if open_ports:
                results.append(HostResult(ip=ip, hostname=None, ports=open_ports))
        return results

    def _is_port_open(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except OSError:
            return False
