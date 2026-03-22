from app.tasks import discovery_tasks


def test_parse_port_csv_filters_invalid_and_dedupes() -> None:
    fallback = (22, 80)
    parsed = discovery_tasks._parse_port_csv("22, 80, 80, 0, 65536, abc, 443", fallback)
    assert parsed == (22, 80, 443)


def test_parse_port_csv_supports_discrete_high_ports() -> None:
    fallback = (22, 80)
    parsed = discovery_tasks._parse_port_csv("10001,20001,30001,40001,50001,20001", fallback)
    assert parsed == (10001, 20001, 30001, 40001, 50001)


def test_parse_port_csv_fallback_when_empty() -> None:
    fallback = (22, 80)
    assert discovery_tasks._parse_port_csv("", fallback) == fallback
    assert discovery_tasks._parse_port_csv(None, fallback) == fallback


def test_build_discovery_config_from_settings(monkeypatch) -> None:
    monkeypatch.setattr(discovery_tasks.settings, "DISCOVERY_LIVENESS_PORTS", "22,443,8443")
    monkeypatch.setattr(discovery_tasks.settings, "DISCOVERY_SERVICE_PORTS", "80,443,3306")
    monkeypatch.setattr(discovery_tasks.settings, "DISCOVERY_HIGH_BACKDOOR_PORTS", "31337,55555")
    monkeypatch.setattr(discovery_tasks.settings, "DISCOVERY_PORTSET_MODE", "top1000_plus_custom")
    monkeypatch.setattr(discovery_tasks.settings, "DISCOVERY_TOP_PORTS_LIMIT", 1000)

    cfg = discovery_tasks._build_discovery_config()
    assert cfg.liveness_ports == (22, 443, 8443)
    assert cfg.service_ports == (80, 443, 3306)
    assert cfg.high_backdoor_ports == (31337, 55555)
    assert cfg.portset_mode == "top1000_plus_custom"
    assert cfg.top_ports_limit == 1000


def test_normalize_open_ports_enforces_backdoor_version_skip(monkeypatch) -> None:
    monkeypatch.setattr(discovery_tasks.settings, "DISCOVERY_HIGH_BACKDOOR_PORTS", "10001,20001")
    host = {
        "ports": [10001],
        "services": [
            {
                "port": 10001,
                "service": "unknown",
                "version": "9.9.9",
                "fingerprint_json": {"source": "py", "backdoor_candidate": True},
            }
        ],
    }

    open_ports, service_map = discovery_tasks._normalize_open_ports_and_services(host)

    assert open_ports == [10001]
    payload = service_map[10001]
    assert payload["version"] is None
    assert payload["fingerprint_json"]["nmap_skipped"] is True
    assert payload["fingerprint_json"]["nmap_skip_reason"] == "backdoor_candidate_policy"
    assert payload["fingerprint_json"]["version_skipped"] is True


def test_normalize_open_ports_port_dict_branch_enforces_backdoor_skip(monkeypatch) -> None:
    monkeypatch.setattr(discovery_tasks.settings, "DISCOVERY_HIGH_BACKDOOR_PORTS", "10001,20001")
    host = {
        "ports": [
            {
                "port": 10001,
                "service_name": "unknown",
                "service_version": "7.7.7",
                "fingerprint_json": {},
            }
        ],
        "services": [],
    }

    open_ports, service_map = discovery_tasks._normalize_open_ports_and_services(host)

    assert open_ports == [10001]
    payload = service_map[10001]
    assert payload["version"] is None
    assert payload["fingerprint_json"]["backdoor_candidate"] is True
    assert payload["fingerprint_json"]["nmap_skipped"] is True
    assert payload["fingerprint_json"]["nmap_skip_reason"] == "backdoor_candidate_policy"
    assert payload["fingerprint_json"]["version_skipped"] is True


def test_build_nmap_targets_skips_backdoor_ports_and_tracks_counts() -> None:
    prepared_hosts = [
        {
            "ip": "10.10.0.5",
            "services": [
                {"port": 31337, "service": "unknown", "confidence": 20, "backdoor_candidate": True},
                {"port": 22, "service": "ssh", "confidence": 60},
            ],
        }
    ]

    targets, low_confidence_count, nmap_skipped_count, backdoor_nmap_blocked_count = discovery_tasks._build_nmap_targets(
        prepared_hosts,
        {31337},
        70,
    )

    assert low_confidence_count == 1
    assert nmap_skipped_count == 1
    assert backdoor_nmap_blocked_count == 1
    assert targets == [{"ip": "10.10.0.5", "ports": [22], "blocked_ports": [31337]}]
