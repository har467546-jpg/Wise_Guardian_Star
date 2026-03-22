import asyncio

from app.scanner.port_scanner import AsyncPortScanner, PortScanResult, ProtocolProbeObservation


def test_probe_liveness_falls_back_to_connect(monkeypatch) -> None:
    scanner = AsyncPortScanner()

    monkeypatch.setattr(scanner, "_can_use_raw_sockets", lambda: True)
    monkeypatch.setattr(scanner, "_probe_with_syn_blocking", lambda ip, port: None)

    async def fake_connect(ip: str, port: int) -> PortScanResult:
        return PortScanResult(port=port, is_open=True, probe_method="connect")

    monkeypatch.setattr(scanner, "_probe_with_connect", fake_connect)

    result = asyncio.run(scanner.probe_liveness("127.0.0.1", 80))

    assert result.is_open is True
    assert result.probe_method == "connect"


def test_scan_host_uses_protocol_probe_result(monkeypatch) -> None:
    scanner = AsyncPortScanner()

    async def fake_probe_service(ip: str, port: int, *, probe_method: str = "connect"):
        from app.scanner.service_fingerprint import fingerprint_service

        return fingerprint_service(
            port=port,
            banner="HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n",
            probe_method=probe_method,
            transport_service="http",
            product_name="nginx",
            product_version="1.24.0",
            evidence=["http_probe"],
            probe_chain=["passive_read", "http_plain"],
        )

    monkeypatch.setattr(scanner, "probe_service", fake_probe_service)

    port_results, service_results = asyncio.run(
        scanner.scan_host(
            "127.0.0.1",
            [8080],
            liveness_results=[PortScanResult(port=8080, is_open=True, probe_method="connect")],
        )
    )

    assert [item.port for item in port_results if item.is_open] == [8080]
    assert service_results[0].service == "nginx"
    assert service_results[0].version == "1.24.0"


def test_probe_service_prefers_http_tls_on_nonstandard_tls_port(monkeypatch) -> None:
    scanner = AsyncPortScanner()

    async def fake_passive(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(probe_name="passive_read")

    async def fake_https(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(
            probe_name="http_tls",
            banner="HTTP/1.1 200 OK\r\nServer: nginx/1.25.5\r\n\r\n",
            certificate_names=["api.lab.example"],
            transport_service="https",
            tls_detected=True,
            evidence=["http_probe"],
        )

    monkeypatch.setattr(scanner, "_probe_passive_read", fake_passive)
    monkeypatch.setattr(scanner, "_probe_http_tls", fake_https)

    fingerprint = asyncio.run(scanner.probe_service("127.0.0.1", 6443, probe_method="connect"))

    assert fingerprint.transport_service == "https"
    assert fingerprint.service == "nginx"
    assert fingerprint.hostname_hint == "api.lab.example"


def test_probe_service_marks_ftp_family(monkeypatch) -> None:
    scanner = AsyncPortScanner()

    async def fake_passive(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(probe_name="passive_read")

    async def fake_ftp(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(
            probe_name="ftp",
            banner="220 (vsFTPd 3.0.3)\r\n",
            transport_service="ftp",
            application_service="ftp",
            evidence=["ftp"],
        )

    monkeypatch.setattr(scanner, "_probe_passive_read", fake_passive)
    monkeypatch.setattr(scanner, "_probe_ftp", fake_ftp)

    fingerprint = asyncio.run(scanner.probe_service("127.0.0.1", 21, probe_method="connect"))

    assert fingerprint.transport_service == "ftp"
    assert fingerprint.service == "vsftpd"
    assert fingerprint.version == "3.0.3"


def test_probe_service_marks_nonstandard_ftp_family(monkeypatch) -> None:
    scanner = AsyncPortScanner()

    async def fake_passive(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(probe_name="passive_read")

    async def fake_ftp(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(
            probe_name="ftp",
            banner="220 ProFTPD 1.3.1 Server\r\n",
            transport_service="ftp",
            application_service="ftp",
            product_name="proftpd",
            evidence=["ftp_probe"],
        )

    monkeypatch.setattr(scanner, "_probe_passive_read", fake_passive)
    monkeypatch.setattr(scanner, "_probe_ftp", fake_ftp)

    fingerprint = asyncio.run(scanner.probe_service("127.0.0.1", 2121, probe_method="connect"))

    assert fingerprint.transport_service == "ftp"
    assert fingerprint.service == "ftp"
    assert fingerprint.product_name == "proftpd"


def test_probe_service_marks_postgresql_family(monkeypatch) -> None:
    scanner = AsyncPortScanner()

    async def fake_passive(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(probe_name="passive_read")

    async def fake_postgresql(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(
            probe_name="postgresql",
            banner="S",
            transport_service="postgresql",
            application_service="postgresql",
            product_name="postgresql",
            tls_detected=True,
            evidence=["postgresql_ssl_response=S"],
        )

    monkeypatch.setattr(scanner, "_probe_passive_read", fake_passive)
    monkeypatch.setattr(scanner, "_probe_postgresql", fake_postgresql)

    fingerprint = asyncio.run(scanner.probe_service("127.0.0.1", 5432, probe_method="connect"))

    assert fingerprint.service == "postgresql"
    assert fingerprint.transport_service == "postgresql"
    assert fingerprint.tls_detected is True


def test_probe_service_marks_rpcbind_ajp_and_rmi_families(monkeypatch) -> None:
    scanner = AsyncPortScanner()

    async def fake_passive(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(probe_name="passive_read")

    async def fake_rpcbind(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(
            probe_name="rpcbind",
            transport_service="rpcbind",
            application_service="rpcbind",
            product_name="rpcbind",
            evidence=["rpcbind_probe"],
        )

    async def fake_ajp(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(
            probe_name="ajp",
            transport_service="ajp13",
            application_service="ajp13",
            product_name="ajp13",
            evidence=["ajp_probe"],
        )

    async def fake_rmi(ip: str, port: int) -> ProtocolProbeObservation:
        return ProtocolProbeObservation(
            probe_name="java_rmi",
            transport_service="java-rmi",
            application_service="java-rmi",
            product_name="java-rmi",
            evidence=["java_rmi_probe"],
        )

    monkeypatch.setattr(scanner, "_probe_passive_read", fake_passive)
    monkeypatch.setattr(scanner, "_probe_rpcbind", fake_rpcbind)
    monkeypatch.setattr(scanner, "_probe_ajp", fake_ajp)
    monkeypatch.setattr(scanner, "_probe_java_rmi", fake_rmi)

    rpcbind = asyncio.run(scanner.probe_service("127.0.0.1", 111, probe_method="connect"))
    ajp = asyncio.run(scanner.probe_service("127.0.0.1", 8009, probe_method="connect"))
    rmi = asyncio.run(scanner.probe_service("127.0.0.1", 1099, probe_method="connect"))

    assert rpcbind.service == "rpcbind"
    assert ajp.service == "ajp13"
    assert rmi.service == "java-rmi"
