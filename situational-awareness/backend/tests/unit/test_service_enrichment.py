from app.scanner.service_enrichment import (
    AsyncNmapServiceEnricher,
    apply_port_risk_annotation,
    build_network_initial_snapshot,
    enrich_python_service_record,
    is_nmap_enrichment_blocked,
    merge_service_records,
    needs_nmap_enrichment,
    to_fingerprint_json,
)


def test_enrich_python_service_record_unknown() -> None:
    record = enrich_python_service_record(
        port=9999,
        record={"service": "unknown", "version": None, "banner": "", "probe_method": "connect"},
        identified_at="2026-03-11T00:00:00+00:00",
    )
    assert record["confidence"] == 20
    assert record["source"] == "py"
    assert needs_nmap_enrichment(record, threshold=70) is True


def test_enrich_python_service_record_port_inference() -> None:
    record = enrich_python_service_record(
        port=22,
        record={"service": "ssh", "version": None, "banner": None, "probe_method": "connect"},
        identified_at="2026-03-11T00:00:00+00:00",
    )
    assert record["confidence"] == 60
    assert needs_nmap_enrichment(record, threshold=70) is True


def test_enrich_python_service_record_product_match() -> None:
    record = enrich_python_service_record(
        port=22,
        record={
            "service": "ssh",
            "version": "9.3",
            "product_name": "openssh",
            "banner": "SSH-2.0-OpenSSH_9.3",
            "probe_method": "connect",
            "probe_chain": ["passive_read", "ssh"],
        },
        identified_at="2026-03-11T00:00:00+00:00",
    )
    assert record["confidence"] == 95
    assert needs_nmap_enrichment(record, threshold=70) is False


def test_merge_prefers_nmap_when_higher_confidence() -> None:
    py_record = {
        "port": 3306,
        "service": "mysql",
        "version": None,
        "source": "py",
        "confidence": 55,
        "reason": "port based",
        "evidence": [],
        "identified_at": "2026-03-11T00:00:00+00:00",
    }
    nmap_record = {
        "port": 3306,
        "service": "mysql",
        "version": "8.0.35",
        "source": "nmap",
        "confidence": 90,
        "reason": "nmap",
        "evidence": ["nmap"],
        "identified_at": "2026-03-11T00:00:01+00:00",
    }
    merged = merge_service_records(py_record, nmap_record)
    assert merged["source"] == "nmap"
    assert merged["version"] == "8.0.35"


def test_merge_ignores_nmap_when_port_is_policy_blocked() -> None:
    py_record = {
        "port": 31337,
        "service": "unknown",
        "source": "py",
        "confidence": 20,
        "evidence": ["py"],
    }
    nmap_record = {
        "port": 31337,
        "service": "http",
        "source": "nmap",
        "confidence": 90,
        "nmap_service": "http",
        "nmap_product": "nginx",
    }
    merged = merge_service_records(py_record, nmap_record, nmap_blocked=True)
    assert merged["source"] == "py"
    assert merged["nmap_service"] is None
    assert merged["nmap_product"] is None


def test_parse_nmap_xml_output() -> None:
    output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Debian 3"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0.35"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    parsed = AsyncNmapServiceEnricher.parse_xml_output("10.10.0.5", output)
    assert parsed[22]["service"] == "ssh"
    assert parsed[22]["nmap_service"] == "ssh"
    assert parsed[3306]["service"] == "mysql"
    assert parsed[3306]["product_version"] == "8.0.35"
    assert parsed[3306]["confidence"] == 90


def test_enrich_hosts_filters_blocked_ports_before_running_nmap(monkeypatch) -> None:
    enricher = AsyncNmapServiceEnricher()
    captured: dict[str, tuple[str, ...]] = {}

    class _DummyProcess:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
            return output.encode("utf-8"), b""

    async def fake_exec(*cmd, **kwargs):
        captured["cmd"] = tuple(str(item) for item in cmd)
        return _DummyProcess()

    monkeypatch.setattr(AsyncNmapServiceEnricher, "_has_nmap", lambda self: True)
    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

    result = __import__("asyncio").run(
        enricher.enrich_hosts(
            [
                {
                    "ip": "10.10.0.5",
                    "ports": [22, 31337],
                    "blocked_ports": [31337],
                }
            ]
        )
    )

    assert result["10.10.0.5"][22]["service"] == "ssh"
    assert "-p" in captured["cmd"]
    assert "22" in captured["cmd"]
    assert "31337" not in captured["cmd"]


def test_build_network_initial_snapshot_summary() -> None:
    summary, detail, status = build_network_initial_snapshot(
        ip="10.10.0.8",
        hostname="db-08",
        services=[
            {"port": 22, "service": "ssh", "confidence": 75},
            {"port": 3306, "service": "mysql", "confidence": 90, "version": "8.0.35"},
        ],
    )
    assert summary["role_guess"] == "Database node"
    assert detail["confidence_breakdown"]["high"] >= 1
    assert status == "success"


def test_build_network_initial_snapshot_marks_dns_service_as_network_infrastructure() -> None:
    summary, detail, status = build_network_initial_snapshot(
        ip="192.168.10.2",
        hostname="gateway.lab",
        services=[
            {
                "port": 53,
                "service": "dns",
                "application_service": "dns",
                "confidence": 80,
            }
        ],
    )

    assert status == "success"
    assert summary["role_guess"] == "Network infrastructure node"
    assert detail["ports"] == [53]


def test_apply_port_risk_annotation_marks_backdoor_candidate() -> None:
    record = {"port": 31337, "service": "unknown", "version": "1.2.3"}
    annotated = apply_port_risk_annotation(record, {31337, 4444})
    assert annotated["port_category"] == "high_backdoor_candidate"
    assert annotated["backdoor_candidate"] is True
    assert "后门" in str(annotated["risk_note"])
    assert annotated["nmap_skipped"] is True
    assert annotated["nmap_skip_reason"] == "backdoor_candidate_policy"
    assert annotated["version"] is None
    assert annotated["version_skipped"] is True


def test_apply_port_risk_annotation_respects_existing_backdoor_flag() -> None:
    record = {
        "port": 6667,
        "service": "irc",
        "version": "3.2.8.1",
        "banner": ":irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...",
        "fingerprint_json": {"backdoor_candidate": True},
    }
    annotated = apply_port_risk_annotation(record, {6667, 31337, 4444})
    assert annotated["backdoor_candidate"] is True
    assert annotated["nmap_skipped"] is False
    assert annotated["version"] == "3.2.8.1"
    assert annotated["version_skipped"] is False


def test_is_nmap_enrichment_blocked_handles_high_ports_and_existing_marks() -> None:
    assert is_nmap_enrichment_blocked(31337, {"service": "unknown"}, {31337}) is True
    assert is_nmap_enrichment_blocked(6667, {"service": "irc", "banner": ":irc.lab NOTICE AUTH"}, {6667}) is False
    assert is_nmap_enrichment_blocked(8080, {"backdoor_candidate": True}, set()) is True
    assert is_nmap_enrichment_blocked(8080, {"service": "http"}, set()) is False


def test_to_fingerprint_json_includes_backdoor_fields() -> None:
    payload = to_fingerprint_json(
        {
            "port": 31337,
            "confidence": 20,
            "reason": "unknown",
            "source": "py",
            "port_category": "high_backdoor_candidate",
            "backdoor_candidate": True,
            "risk_note": "命中高位后门特征端口列表",
            "nmap_skipped": True,
            "nmap_skip_reason": "backdoor_candidate_policy",
        }
    )
    assert payload["port_category"] == "high_backdoor_candidate"
    assert payload["backdoor_candidate"] is True
    assert payload["risk_note"] == "命中高位后门特征端口列表"
    assert payload["nmap_skipped"] is True
    assert payload["nmap_skip_reason"] == "backdoor_candidate_policy"


def test_to_fingerprint_json_preserves_nse_results_and_summary() -> None:
    payload = to_fingerprint_json(
        {
            "port": 21,
            "confidence": 95,
            "reason": "原生协议探测识别到产品与版本",
            "source": "py",
            "nse": {
                "ftp-anon": {
                    "hit": True,
                    "summary": "Anonymous FTP login allowed",
                    "anonymous_allowed": True,
                    "raw_output": "Anonymous FTP login allowed",
                }
            },
            "nse_summary": {
                "requested_scripts": ["ftp-anon", "ftp-syst"],
                "hit_scripts": ["ftp-anon"],
                "script_count": 2,
                "hit_count": 1,
                "script_summaries": {"ftp-anon": "Anonymous FTP login allowed"},
            },
            "nse_last_phase": "collection",
            "nse_last_collected_at": "2026-03-13T10:00:00+00:00",
        }
    )

    assert payload["nse"]["ftp-anon"]["hit"] is True
    assert "raw_output" not in payload["nse"]["ftp-anon"]
    assert payload["nse_summary"]["hit_count"] == 1
    assert payload["nse_last_phase"] == "collection"
    assert payload["nse_last_collected_at"] == "2026-03-13T10:00:00+00:00"


def test_to_fingerprint_json_includes_service_aliases() -> None:
    payload = to_fingerprint_json(
        {
            "port": 80,
            "service": "phpmyadmin",
            "transport_service": "http",
            "application_service": "phpmyadmin",
            "product_name": "phpmyadmin",
            "product_version": "2.2.8",
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.2.8\r\nX-Powered-By: PHP/5.2.4\r\n\r\n",
        }
    )

    assert "phpmyadmin" in payload["service_aliases"]
    assert "apache" in payload["service_aliases"]
    assert "php" in payload["service_aliases"]
