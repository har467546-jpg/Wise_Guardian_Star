import asyncio

from app.scanner.web_exposure import (
    AsyncWebExposureScanner,
    WebExposureConfig,
    merge_web_exposure_into_services,
)


def test_web_exposure_collects_http_metadata_from_local_server() -> None:
    async def _run() -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(1024)
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Server: nginx/1.24.0\r\n"
                b"Location: http://app.lab.local/home\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"<html><head><title> Lab Portal </title></head><body>ok</body></html>"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            scanner = AsyncWebExposureScanner(WebExposureConfig(connect_timeout=1.0, read_timeout=1.0))
            result = await scanner.enrich_hosts(
                [
                    {
                        "ip": "127.0.0.1",
                        "hostname": "app.lab.local",
                        "services": [
                            {
                                "port": port,
                                "service": "http",
                                "transport_service": "http",
                                "service_aliases": ["http"],
                            }
                        ],
                    }
                ]
            )
        finally:
            server.close()
            await server.wait_closed()

        web = result["127.0.0.1"][port]
        assert web["scheme"] == "http"
        assert web["status_code"] == 200
        assert web["title"] == "Lab Portal"
        assert web["server"] == "nginx/1.24.0"
        assert web["location"] == "http://app.lab.local/home"
        assert web["hostname_hint"] == "app.lab.local"
        assert "web_probe" in web["evidence"]

    asyncio.run(_run())


def test_web_exposure_detects_cdn_from_cname(monkeypatch) -> None:
    async def fake_probe_target(self, *, ip, port, scheme, hostname, dns):
        from app.scanner.web_exposure import WebExposureResult, _build_cdn_info

        return WebExposureResult(
            port=port,
            scheme=scheme,
            url=f"{scheme}://{hostname}:{port}/",
            hostname_hint=hostname,
            dns=dns,
            cdn=_build_cdn_info(dns),
            evidence=["web_probe"],
        )

    monkeypatch.setattr(
        "app.scanner.web_exposure._resolve_dns_blocking",
        lambda hostname: {
            "hostname": hostname,
            "cnames": ["assets.example.com.cdn.cloudflare.net"],
            "addresses": ["203.0.113.10"],
            "address_count": 1,
        },
    )
    monkeypatch.setattr(AsyncWebExposureScanner, "_probe_target", fake_probe_target)

    result = asyncio.run(
        AsyncWebExposureScanner().enrich_hosts(
            [
                {
                    "ip": "203.0.113.10",
                    "hostname": "assets.example.com",
                    "services": [{"port": 443, "service": "https", "tls_detected": True}],
                }
            ]
        )
    )

    web = result["203.0.113.10"][443]
    assert web["dns"]["cnames"] == ["assets.example.com.cdn.cloudflare.net"]
    assert web["cdn"]["detected"] is True
    assert web["cdn"]["provider_hint"] == "cloudflare"


def test_web_exposure_ignores_non_web_services() -> None:
    result = asyncio.run(
        AsyncWebExposureScanner().enrich_hosts(
            [
                {
                    "ip": "127.0.0.1",
                    "services": [
                        {"port": 22, "service": "ssh"},
                        {"port": 3306, "service": "mysql"},
                    ],
                }
            ]
        )
    )

    assert result == {}


def test_merge_web_exposure_into_services_adds_web_metadata_and_hostname() -> None:
    hosts = [
        {
            "ip": "10.10.0.5",
            "services": [
                {
                    "port": 80,
                    "service": "http",
                    "evidence": ["port=80"],
                }
            ],
        }
    ]

    count = merge_web_exposure_into_services(
        hosts,
        {
            "10.10.0.5": {
                80: {
                    "port": 80,
                    "scheme": "http",
                    "url": "http://app.lab/",
                    "status_code": 200,
                    "title": "App",
                    "hostname_hint": "app.lab",
                    "evidence": ["web_probe", "http_status=200"],
                }
            }
        },
    )

    service = hosts[0]["services"][0]
    assert count == 1
    assert service["web"]["title"] == "App"
    assert service["hostname_hint"] == "app.lab"
    assert service["evidence"] == ["port=80", "web_probe", "http_status=200"]
