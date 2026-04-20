import asyncio
from types import SimpleNamespace

import pytest

from app.scanner.network_discovery import (
    AsyncNetworkDiscovery,
    DiscoveryConfig,
    DiscoveryLivenessError,
    DiscoveryResult,
)
from app.scanner.port_scanner import PortScanResult, ServiceProbeResult
from app.scanner.service_fingerprint import ServiceFingerprint


def test_discover_raises_for_invalid_cidr() -> None:
    scanner = AsyncNetworkDiscovery()
    with pytest.raises(ValueError):
        asyncio.run(scanner.discover("not-a-cidr"))


def test_parse_nmap_ping_xml_output_returns_only_up_ipv4_hosts() -> None:
    parsed = AsyncNetworkDiscovery.parse_nmap_ping_xml_output(
        """
        <nmaprun>
          <host>
            <status state="up" />
            <address addr="10.10.0.2" addrtype="ipv4" />
          </host>
          <host>
            <status state="down" />
            <address addr="10.10.0.1" addrtype="ipv4" />
          </host>
          <host>
            <status state="up" />
            <address addr="fe80::1" addrtype="ipv6" />
          </host>
          <host>
            <status state="up" />
            <address addr="10.10.0.3" addrtype="ipv4" />
          </host>
        </nmaprun>
        """
    )

    assert parsed == ["10.10.0.2", "10.10.0.3"]


def test_parse_nmap_ping_xml_output_raises_for_invalid_xml() -> None:
    with pytest.raises(DiscoveryLivenessError, match="XML"):
        AsyncNetworkDiscovery.parse_nmap_ping_xml_output("<nmaprun")


def test_parse_nmap_full_scan_xml_output_returns_open_tcp_ports() -> None:
    parsed = AsyncNetworkDiscovery.parse_nmap_full_scan_xml_output(
        "10.10.0.5",
        """
        <nmaprun>
          <host>
            <address addr="10.10.0.5" addrtype="ipv4" />
            <ports>
              <port protocol="tcp" portid="22"><state state="open" /></port>
              <port protocol="tcp" portid="80"><state state="closed" /></port>
              <port protocol="udp" portid="161"><state state="open" /></port>
            </ports>
          </host>
        </nmaprun>
        """,
    )

    assert parsed == [22]


def test_parse_arp_scan_output_returns_ipv4_hosts() -> None:
    parsed = AsyncNetworkDiscovery.parse_arp_scan_output(
        """
        10.10.0.2\t00:11:22:33:44:55\tVendor
        Interface: eth0
        10.10.0.3\t00:11:22:33:44:56\tVendor
        """
    )

    assert parsed == ["10.10.0.2", "10.10.0.3"]


def test_discover_live_hosts_with_nmap_builds_expected_command(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(liveness_mode="nmap_icmp"))
    captured: dict[str, tuple[str, ...]] = {}

    class _FakeProcess:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"<nmaprun />", b""

    async def fake_create_subprocess_exec(*cmd, stdout=None, stderr=None):
        captured["cmd"] = tuple(cmd)
        return _FakeProcess()

    monkeypatch.setattr(scanner, "_has_nmap", lambda: True)
    monkeypatch.setattr("app.scanner.network_discovery.asyncio.create_subprocess_exec", fake_create_subprocess_exec)

    result = asyncio.run(scanner._discover_live_hosts_with_nmap("10.10.0.0/30"))

    assert result == []
    assert captured["cmd"] == (
        "nmap",
        "-sn",
        "-n",
        "-PE",
        "-PS22,80,443,445,3389",
        "-PA80,443,445,3389",
        "-T4",
        "--min-rate",
        "100000",
        "10.10.0.0/30",
        "-oX",
        "-",
    )


def test_discover_live_hosts_with_nmap_raises_when_nmap_missing(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(liveness_mode="nmap_icmp"))
    monkeypatch.setattr(scanner, "_has_nmap", lambda: False)

    with pytest.raises(DiscoveryLivenessError, match="nmap"):
        asyncio.run(scanner._discover_live_hosts_with_nmap("10.10.0.0/30"))


def test_discovery_prefers_service_hostname(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(host_concurrency=8, liveness_mode="hybrid"))

    async def fake_icmp(ip: str) -> bool:
        return ip.endswith(".1")

    async def fake_tcp_probe(ip: str) -> list[PortScanResult]:
        return [PortScanResult(port=443, is_open=ip.endswith(".2"), probe_method="connect")]

    async def fake_scan_host(ip: str, ports: list[int], liveness_results: list[PortScanResult] | None = None):
        if ip.endswith(".1"):
            fingerprint = ServiceFingerprint(
                port=443,
                service="https",
                banner="HTTP/1.1 200 OK",
                version=None,
                hostname_hint="svc.lab.example",
                probe_method="connect",
            )
            service = ServiceProbeResult(
                port=443,
                service="https",
                banner="HTTP/1.1 200 OK",
                version=None,
                hostname_hint="svc.lab.example",
                probe_method="connect",
                fingerprint=fingerprint,
            )
            return [PortScanResult(port=443, is_open=True, probe_method="connect")], [service]
        return liveness_results or [], []

    monkeypatch.setattr(scanner, "icmp_ping", fake_icmp)
    monkeypatch.setattr(scanner, "tcp_host_probe", fake_tcp_probe)
    monkeypatch.setattr(scanner.port_scanner, "scan_host", fake_scan_host)

    results = asyncio.run(scanner.discover("10.10.0.0/30"))

    assert [item.ip for item in results] == ["10.10.0.1", "10.10.0.2"]
    assert results[0].hostname == "svc.lab.example"
    assert results[1].hostname is None
    assert results[0].ports == [443]
    assert results[1].ports == [443]


def test_discover_nmap_icmp_skips_service_scan(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(host_concurrency=8, liveness_mode="nmap_icmp"))
    scan_host_calls = {"count": 0}
    batch_calls = {"count": 0}

    async def fake_discover_live_hosts(cidr: str) -> list[str]:
        batch_calls["count"] += 1
        assert cidr == "10.10.0.0/30"
        return ["10.10.0.1", "10.10.0.2"]

    async def fake_scan_host(ip: str, ports: list[int], liveness_results: list[PortScanResult] | None = None):
        scan_host_calls["count"] += 1
        return liveness_results or [], []

    monkeypatch.setattr(scanner, "_discover_live_hosts_with_nmap", fake_discover_live_hosts)
    monkeypatch.setattr(scanner.port_scanner, "scan_host", fake_scan_host)

    results = asyncio.run(scanner.discover("10.10.0.0/30", include_services=False))

    assert len(results) == 2
    assert batch_calls["count"] == 1
    assert scan_host_calls["count"] == 0
    assert all(item.ports == [] for item in results)
    assert all(item.services == [] for item in results)
    assert all(item.hostname is None for item in results)


def test_discover_icmp_only_alias_uses_nmap_liveness(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(host_concurrency=8, liveness_mode="icmp_only"))
    batch_calls = {"count": 0}

    async def fake_discover_live_hosts(cidr: str) -> list[str]:
        batch_calls["count"] += 1
        assert cidr == "10.10.0.0/30"
        return ["10.10.0.1"]

    monkeypatch.setattr(scanner, "_discover_live_hosts_with_nmap", fake_discover_live_hosts)

    results = asyncio.run(scanner.discover("10.10.0.0/30", include_services=False))

    assert batch_calls["count"] == 1
    assert [item.ip for item in results] == ["10.10.0.1"]
    assert results[0].hostname is None


def test_discover_nmap_icmp_scans_services_only_for_live_hosts(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(host_concurrency=8, liveness_mode="nmap_icmp"))
    captured: dict[str, list[dict[str, str]]] = {}

    async def fake_discover_live_hosts(cidr: str) -> list[str]:
        assert cidr == "10.10.0.0/30"
        return ["10.10.0.1"]

    async def fake_scan_known_hosts(hosts: list[dict[str, str]]) -> list[DiscoveryResult]:
        captured["hosts"] = hosts
        return [DiscoveryResult(ip="10.10.0.1", hostname="svc.lab.example", ports=[443], services=[])]

    monkeypatch.setattr(scanner, "_discover_live_hosts_with_nmap", fake_discover_live_hosts)
    monkeypatch.setattr(scanner, "scan_known_hosts", fake_scan_known_hosts)

    results = asyncio.run(scanner.discover("10.10.0.0/30", include_services=True))

    assert captured["hosts"] == [
        {
            "ip": "10.10.0.1",
            "discovery_sources": ["nmap_host_discovery"],
            "discovery_evidence": ["nmap_host_discovery:10.10.0.1"],
        }
    ]
    assert len(results) == 1
    assert results[0].hostname == "svc.lab.example"
    assert results[0].ports == [443]


def test_discover_multi_source_merges_arp_fping_and_nmap(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(liveness_mode="multi_source", enable_arp_discovery=True, enable_fping=True))

    monkeypatch.setattr("app.scanner.network_discovery.find_local_ipv4_interface_for_network", lambda network: SimpleNamespace(name="eth0"))
    monkeypatch.setattr(scanner, "_has_arp_scan", lambda: True)
    monkeypatch.setattr(scanner, "_has_arping", lambda: False)
    monkeypatch.setattr(scanner, "_has_fping", lambda: True)
    monkeypatch.setattr(scanner, "_has_nmap", lambda: True)

    async def fake_arp_scan(cidr: str, *, interface_name: str):
        assert cidr == "10.10.0.0/30"
        assert interface_name == "eth0"
        return ["10.10.0.1"]

    async def fake_fping(cidr: str):
        assert cidr == "10.10.0.0/30"
        return ["10.10.0.2"]

    async def fake_nmap(cidr: str):
        assert cidr == "10.10.0.0/30"
        return ["10.10.0.1", "10.10.0.2"]

    monkeypatch.setattr(scanner, "_discover_live_hosts_with_arp_scan", fake_arp_scan)
    monkeypatch.setattr(scanner, "_discover_live_hosts_with_fping", fake_fping)
    monkeypatch.setattr(scanner, "_discover_live_hosts_with_nmap", fake_nmap)

    results = asyncio.run(scanner.discover("10.10.0.0/30", include_services=False))

    assert [item.ip for item in results] == ["10.10.0.1", "10.10.0.2"]
    assert results[0].discovery_sources == ["arp_scan", "nmap_host_discovery"]
    assert results[1].discovery_sources == ["fping", "nmap_host_discovery"]


def test_network_discovery_expands_scan_ports_in_top1000_mode(monkeypatch) -> None:
    monkeypatch.setattr("app.scanner.network_discovery.resolve_scan_ports", lambda **_: (21, 22, 80, 443, 31337))

    scanner = AsyncNetworkDiscovery(
        DiscoveryConfig(
            service_ports=(443,),
            high_backdoor_ports=(31337,),
            portset_mode="top1000_plus_custom",
            top_ports_limit=1000,
        )
    )

    assert scanner._scan_ports == [21, 22, 80, 443, 31337]


def test_scan_known_hosts_ports_only_returns_open_ports_without_services(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(
        DiscoveryConfig(
            full_scan_host_concurrency=2,
            portset_mode="curated",
            service_ports=(22, 80),
        )
    )

    async def fake_scan_ports(ip: str, ports: list[int]):
        assert ports == list(scanner.scan_ports)
        return [
            PortScanResult(port=22, is_open=True, probe_method="syn"),
            PortScanResult(port=80, is_open=False, probe_method="syn"),
        ]

    monkeypatch.setattr(scanner.port_scanner, "scan_ports", fake_scan_ports)

    results = asyncio.run(scanner.scan_known_hosts_ports_only([{"ip": "10.10.0.5"}]))

    assert len(results) == 1
    assert results[0].ports == [22]
    assert results[0].services == []
    assert results[0].hostname is None


def test_scan_known_hosts_ports_only_prefers_nmap_for_full_scan(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(full_scan_host_concurrency=2, portset_mode="full"))
    captured: dict[str, tuple[str, ...]] = {}

    class _FakeProcess:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return (
                b"""
                <nmaprun>
                  <host>
                    <address addr=\"10.10.0.5\" addrtype=\"ipv4\" />
                    <ports>
                      <port protocol=\"tcp\" portid=\"22\"><state state=\"open\" /></port>
                      <port protocol=\"tcp\" portid=\"80\"><state state=\"closed\" /></port>
                    </ports>
                  </host>
                </nmaprun>
                """,
                b"",
            )

    async def fake_create_subprocess_exec(*cmd, stdout=None, stderr=None):
        captured["cmd"] = tuple(cmd)
        return _FakeProcess()

    monkeypatch.setattr(scanner, "_has_nmap", lambda: True)
    monkeypatch.setattr("app.scanner.network_discovery.asyncio.create_subprocess_exec", fake_create_subprocess_exec)

    results = asyncio.run(scanner.scan_known_hosts_ports_only([{"ip": "10.10.0.5", "hostname": "seed.lab.example"}]))

    assert captured["cmd"] == (
        "nmap",
        "-Pn",
        "-n",
        "-T5",
        "--min-rate",
        "100000",
        "--open",
        "-p-",
        "10.10.0.5",
        "-oX",
        "-",
    )
    assert len(results) == 1
    assert results[0].ports == [22]
    assert results[0].hostname == "seed.lab.example"


def test_probe_known_open_ports_only_probes_supplied_open_ports(monkeypatch) -> None:
    scanner = AsyncNetworkDiscovery(DiscoveryConfig(service_probe_host_concurrency=2))
    captured: dict[str, list[int]] = {}

    async def fake_probe_services(ip: str, port_results: list[PortScanResult]):
        captured["ports"] = [item.port for item in port_results]
        fingerprint = ServiceFingerprint(
            port=22,
            service="ssh",
            banner="SSH-2.0-OpenSSH_8.9",
            version="8.9",
            hostname_hint="svc.lab.example",
            probe_method="connect",
        )
        return [
            ServiceProbeResult(
                port=22,
                service="ssh",
                banner="SSH-2.0-OpenSSH_8.9",
                version="8.9",
                hostname_hint="svc.lab.example",
                probe_method="connect",
                fingerprint=fingerprint,
            )
        ]

    monkeypatch.setattr(scanner.port_scanner, "probe_services", fake_probe_services)

    results = asyncio.run(
        scanner.probe_known_open_ports(
            [{"ip": "10.10.0.5", "hostname": "seed.lab.example", "ports": [22, 80]}]
        )
    )

    assert captured["ports"] == [22, 80]
    assert len(results) == 1
    assert results[0].ports == [22, 80]
    assert results[0].hostname == "svc.lab.example"
    assert results[0].services[0]["port"] == 22
