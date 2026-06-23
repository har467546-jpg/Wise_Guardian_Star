from types import SimpleNamespace

from app.db.models.asset import Asset, AssetPort
from app.db.models.enums import DiscoveryJobStatus
from app.tasks import discovery_tasks


class _FakeDB:
    def __init__(self, job, assets=None):
        self.job = job
        self.assets = list(assets or [])
        self.added: list[object] = []
        self.committed = False
        self.flushed = False
        self.scalar_calls = 0
        self.executed: list[object] = []

    def get(self, model, job_id):
        return self.job if self.job and self.job.id == job_id else None

    def scalar(self, _stmt):
        self.scalar_calls += 1
        return None

    def execute(self, stmt):
        self.executed.append(stmt)
        return SimpleNamespace(rowcount=0)

    def scalars(self, _stmt):
        return SimpleNamespace(all=lambda: list(self.assets))

    def add(self, item) -> None:
        self.added.append(item)

    def flush(self) -> None:
        self.flushed = True

    def commit(self) -> None:
        self.committed = True

    def delete(self, item) -> None:
        self.added.append(("deleted", item))


class _FakeSessionLocal:
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return self

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


def test_filter_excluded_local_hosts_returns_non_local_only(monkeypatch) -> None:
    monkeypatch.setattr(
        discovery_tasks,
        "resolve_local_asset",
        lambda ip, hostname=None: (True, "匹配平台本机 IP") if ip == "192.168.10.5" else (False, None),
    )

    filtered, excluded = discovery_tasks._filter_excluded_local_hosts(
        [
            {"ip": "192.168.10.5", "hostname": "scanner-host"},
            {"ip": "192.168.10.88", "hostname": "target-host"},
        ]
    )

    assert filtered == [{"ip": "192.168.10.88", "hostname": "target-host"}]
    assert excluded == [{"ip": "192.168.10.5", "hostname": "scanner-host", "reason": "匹配平台本机 IP"}]


def test_filter_excluded_local_hosts_no_longer_skips_gateway_candidate(monkeypatch) -> None:
    monkeypatch.setattr(
        discovery_tasks,
        "resolve_local_asset",
        lambda ip, hostname=None: (False, None),
    )

    filtered, excluded = discovery_tasks._filter_excluded_local_hosts(
        [
            {"ip": "192.168.10.254", "hostname": "gateway-host"},
            {"ip": "192.168.10.88", "hostname": "target-host"},
        ],
        cidr="192.168.10.0/24",
    )

    assert filtered == [
        {"ip": "192.168.10.254", "hostname": "gateway-host"},
        {"ip": "192.168.10.88", "hostname": "target-host"},
    ]
    assert excluded == []


def test_discover_hosts_retains_boundary_addresses_without_explicit_local_evidence(monkeypatch) -> None:
    job = SimpleNamespace(
        id="job-discover-1",
        cidr="192.168.10.0/24",
        status=DiscoveryJobStatus.PENDING,
        summary_json={},
        started_at=None,
    )
    db = _FakeDB(job)

    class _FakeHost:
        def __init__(self, ip, hostname):
            self.ip = ip
            self.hostname = hostname

        def to_dict(self):
            return {"ip": self.ip, "hostname": self.hostname, "ports": [], "services": []}

    class _FakeScanner:
        def __init__(self, config):
            self.config = config

        async def discover(self, cidr, include_services=False):
            assert cidr == "192.168.10.0/24"
            assert include_services is False
            return [
                _FakeHost("192.168.10.254", "gateway-host"),
                _FakeHost("192.168.10.88", "target-host"),
            ]

    monkeypatch.setattr(
        discovery_tasks,
        "resolve_local_asset",
        lambda ip, hostname=None: (False, None),
    )
    monkeypatch.setattr(discovery_tasks, "SessionLocal", _FakeSessionLocal(db))
    monkeypatch.setattr(discovery_tasks, "AsyncNetworkDiscovery", _FakeScanner)

    result = discovery_tasks.discover_hosts("job-discover-1")

    assert result == "job-discover-1"
    assert job.summary_json["host_count"] == 2
    assert job.summary_json["hosts"] == [
        {"ip": "192.168.10.254", "hostname": "gateway-host", "ports": [], "services": []},
        {"ip": "192.168.10.88", "hostname": "target-host", "ports": [], "services": []},
    ]
    assert job.summary_json["excluded_local_ip_count"] == 0
    assert job.summary_json["excluded_local_hosts"] == []
    assert db.committed is True


def test_filter_excluded_local_hosts_skips_explicit_runner_local_ip(monkeypatch) -> None:
    monkeypatch.setattr(
        discovery_tasks,
        "resolve_local_asset",
        lambda ip, hostname=None: (False, None),
    )

    filtered, excluded = discovery_tasks._filter_excluded_local_hosts(
        [
            {"ip": "192.168.10.5", "hostname": "scan-node"},
            {"ip": "192.168.10.88", "hostname": "target-host"},
        ],
        local_node_hints={"ips": ["192.168.10.5"], "hostnames": ["scan-node"]},
    )

    assert filtered == [{"ip": "192.168.10.88", "hostname": "target-host"}]
    assert excluded == [{"ip": "192.168.10.5", "hostname": "scan-node", "reason": "匹配扫描节点本机 IP"}]


def test_upsert_assets_skips_local_ip(monkeypatch) -> None:
    job = SimpleNamespace(
        id="job-1",
        cidr="192.168.10.0/24",
        status=DiscoveryJobStatus.PENDING,
        summary_json={
            "hosts": [
                {"ip": "192.168.10.5", "hostname": "scanner-host", "ports": [22], "services": []},
                {"ip": "192.168.10.88", "hostname": "target-host", "ports": [80], "services": []},
            ]
        },
    )
    db = _FakeDB(job)

    monkeypatch.setattr(
        discovery_tasks,
        "resolve_local_asset",
        lambda ip, hostname=None: (True, "匹配平台本机 IP") if ip == "192.168.10.5" else (False, None),
    )
    monkeypatch.setattr(discovery_tasks, "SessionLocal", _FakeSessionLocal(db))
    monkeypatch.setattr(discovery_tasks, "_upsert_asset_ports", lambda db, asset, host: None)

    result = discovery_tasks.upsert_assets("job-1")

    created_assets = [item for item in db.added if isinstance(item, Asset)]
    created_ips = {str(item.ip) for item in created_assets}

    assert result == "job-1"
    assert created_ips == {"192.168.10.88"}
    assert db.scalar_calls == 1
    assert job.summary_json["excluded_local_ip_count"] == 1
    assert job.summary_json["excluded_local_hosts"][0]["ip"] == "192.168.10.5"
    assert db.committed is True


def test_purge_excluded_local_assets_keeps_runner_assets() -> None:
    asset_with_runner = SimpleNamespace(id="asset-runner", ip="192.168.10.5", host_runner=SimpleNamespace(id="runner-1"))
    plain_asset = SimpleNamespace(id="asset-plain", ip="192.168.10.6", host_runner=None)
    db = _FakeDB(None, assets=[asset_with_runner, plain_asset])

    removed = discovery_tasks._purge_excluded_local_assets(
        db,
        [
            {"ip": "192.168.10.5"},
            {"ip": "192.168.10.6"},
        ],
    )

    assert removed == 1
    assert db.added == [("deleted", plain_asset)]


def test_upsert_asset_ports_strips_null_bytes_from_fingerprint_json() -> None:
    db = _FakeDB(None)
    asset = Asset(id="asset-1", ip="192.168.10.88")
    asset.ports = []

    discovery_tasks._upsert_asset_ports(
        db,
        asset,
        {
            "ports": [3306],
            "services": [
                {
                    "port": 3306,
                    "service": "mysql",
                    "version": "8.0.35",
                    "fingerprint_json": {
                        "banner": "mysql\x00handshake",
                        "evidence": ["greeting\x00packet"],
                    },
                }
            ],
        },
    )

    added_ports = [item for item in db.added if isinstance(item, AssetPort)]

    assert len(added_ports) == 1
    assert added_ports[0].service_name == "mysql"
    assert added_ports[0].fingerprint_json["banner"] == "mysqlhandshake"
    assert added_ports[0].fingerprint_json["evidence"] == ["greetingpacket"]


def test_upsert_asset_ports_closes_stale_ports_inside_scan_scope() -> None:
    db = _FakeDB(None)
    asset = Asset(id="asset-2", ip="192.168.10.90")
    stale_port = AssetPort(asset_id=asset.id, port=22, protocol="tcp", state="open", fingerprint_json={})
    asset.ports = [stale_port]

    stats = discovery_tasks._upsert_asset_ports(
        db,
        asset,
        {
            "ports": [80],
            "services": [{"port": 80, "service": "http", "fingerprint_json": {}}],
            "scan_scope": {"protocol": "tcp", "scope_kind": "explicit", "ports": [22, 80], "scanned_port_count": 2},
        },
    )

    assert stale_port.state == "closed"
    assert stats["closed_port_count"] == 1
    assert stats["reconciled_stale_port_count"] == 1


def test_full_port_scan_updates_summary_and_creates_skeleton_ports(monkeypatch) -> None:
    job = SimpleNamespace(
        id="job-full-scan-1",
        cidr="192.168.10.0/24",
        status=DiscoveryJobStatus.PENDING,
        summary_json={
            "hosts": [{"ip": "192.168.10.88", "hostname": "target-host"}],
        },
    )
    asset = Asset(id="asset-1", ip="192.168.10.88", hostname="target-host")
    asset.ports = []
    db = _FakeDB(job, assets=[asset])

    class _FakeScanner:
        def __init__(self, config):
            self.config = config

        @property
        def scan_ports(self):
            return (1, 2, 3, 4)

        async def scan_known_hosts_ports_only(self, hosts):
            return [
                SimpleNamespace(
                    ip="192.168.10.88",
                    hostname="target-host",
                    ports=[22, 80],
                    services=[],
                )
            ]

    monkeypatch.setattr(discovery_tasks, "SessionLocal", _FakeSessionLocal(db))
    monkeypatch.setattr(discovery_tasks, "AsyncNetworkDiscovery", _FakeScanner)

    result = discovery_tasks.full_port_scan("job-full-scan-1")

    added_ports = [item for item in db.added if isinstance(item, AssetPort)]

    assert result == "job-full-scan-1"
    assert job.summary_json["hosts"][0]["ports"] == [22, 80]
    assert job.summary_json["hosts"][0]["services"] == []
    assert job.summary_json["port_scan_stats"]["open_port_count"] == 2
    assert job.summary_json["port_scan_stats"]["scanned_port_count"] == 4
    assert {item.port for item in added_ports} == {22, 80}
    assert all(item.service_name is None for item in added_ports)


def test_probe_open_services_uses_only_open_ports_for_followup(monkeypatch) -> None:
    job = SimpleNamespace(
        id="job-probe-1",
        cidr="192.168.10.0/24",
        status=DiscoveryJobStatus.PENDING,
        summary_json={
            "hosts": [{"ip": "192.168.10.88", "hostname": "target-host", "ports": [22, 80], "services": []}],
            "port_scan_stats": {
                "host_count": 1,
                "open_port_count": 2,
                "scanned_port_count": 65535,
                "service_probe_target_count": 2,
            },
        },
    )
    asset = Asset(id="asset-1", ip="192.168.10.88", hostname="target-host")
    asset.ports = [
        AssetPort(asset_id=asset.id, port=22, protocol="tcp", state="open", fingerprint_json={}),
        AssetPort(asset_id=asset.id, port=80, protocol="tcp", state="open", fingerprint_json={}),
    ]
    db = _FakeDB(job, assets=[asset])
    captured: dict[str, object] = {}

    class _FakeScanner:
        def __init__(self, config):
            self.config = config

        async def probe_known_open_ports(self, hosts):
            captured["probe_hosts"] = hosts
            return [
                SimpleNamespace(
                    ip="192.168.10.88",
                    hostname="target-host",
                    ports=[22, 80],
                    services=[
                        {
                            "port": 22,
                            "service": "ssh",
                            "banner": "SSH-2.0-OpenSSH_8.9",
                            "product_name": "openssh",
                            "product_version": "8.9",
                            "probe_method": "connect",
                            "probe_chain": ["passive_read", "ssh"],
                        },
                        {
                            "port": 80,
                            "service": "http",
                            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
                            "product_name": "nginx",
                            "probe_method": "connect",
                            "probe_chain": ["passive_read", "http_plain"],
                        },
                    ],
                )
            ]

    class _FakeNmapEnricher:
        def __init__(self, *args, **kwargs):
            return None

        async def enrich_hosts(self, targets):
            captured["nmap_targets"] = targets
            return {}

    class _FakeNseEnricher:
        def __init__(self, *args, **kwargs):
            return None

        async def enrich_hosts(self, targets):
            captured["nse_targets"] = targets
            return SimpleNamespace(by_host={}, error_count=0)

    class _FakeWebExposureScanner:
        def __init__(self, *args, **kwargs):
            return None

        async def enrich_hosts(self, hosts):
            captured["web_hosts"] = hosts
            return {
                "192.168.10.88": {
                    80: {
                        "port": 80,
                        "scheme": "http",
                        "url": "http://target-host/",
                        "status_code": 200,
                        "title": "Target Portal",
                        "server": "nginx/1.24.0",
                        "hostname_hint": "target-host",
                        "dns": {
                            "hostname": "target-host",
                            "cnames": ["target-host.cdn.cloudflare.net"],
                            "addresses": ["192.168.10.88"],
                            "address_count": 1,
                        },
                        "cdn": {
                            "detected": True,
                            "provider_hint": "cloudflare",
                            "matched_keyword": "cloudflare",
                            "reason": "cname_keyword",
                        },
                        "evidence": ["web_probe", "http_status=200", "cdn=cloudflare"],
                    }
                }
            }

    monkeypatch.setattr(discovery_tasks, "SessionLocal", _FakeSessionLocal(db))
    monkeypatch.setattr(discovery_tasks, "AsyncNetworkDiscovery", _FakeScanner)
    monkeypatch.setattr(discovery_tasks, "AsyncNmapServiceEnricher", _FakeNmapEnricher)
    monkeypatch.setattr(discovery_tasks, "AsyncNmapScriptEnricher", _FakeNseEnricher)
    monkeypatch.setattr(discovery_tasks, "AsyncWebExposureScanner", _FakeWebExposureScanner)
    monkeypatch.setattr(
        discovery_tasks,
        "select_nse_scripts_for_record",
        lambda record, include_vuln=True: ["ssh2-enum-algos"] if int(record.get("port") or 0) == 22 else ["http-title"],
    )

    result = discovery_tasks.probe_open_services("job-probe-1")

    assert result == "job-probe-1"
    assert asset.status.value == "online"
    assert captured["probe_hosts"] == [{"ip": "192.168.10.88", "hostname": "target-host", "ports": [22, 80], "services": []}]
    assert captured["nmap_targets"] == [{"ip": "192.168.10.88", "ports": [80]}]
    assert captured["nse_targets"] == [{"ip": "192.168.10.88", "ports": [22, 80], "scripts": ["http-title", "ssh2-enum-algos"], "port_scripts": {22: ["ssh2-enum-algos"], 80: ["http-title"]}}]
    assert captured["web_hosts"][0]["services"]
    assert job.summary_json["hosts"][0]["services"]
    http_service = next(item for item in job.summary_json["hosts"][0]["services"] if item["port"] == 80)
    assert http_service["web"]["title"] == "Target Portal"
    assert http_service["web"]["cdn"]["provider_hint"] == "cloudflare"
    http_asset_port = next(item for item in asset.ports if item.port == 80)
    assert http_asset_port.fingerprint_json["web"]["title"] == "Target Portal"
    assert http_asset_port.fingerprint_json["web"]["cdn"]["detected"] is True
    assert job.summary_json["service_enrichment_stats"]["web_exposure_enriched_count"] == 1
    assert job.summary_json["service_enrichment_stats"]["web_exposure_cdn_count"] == 1
    assert job.summary_json["service_enrichment_stats"]["network_initial_snapshot_count"] == 1


def test_probe_open_services_labels_gateway_dns_assets_as_network_infrastructure(monkeypatch) -> None:
    job = SimpleNamespace(
        id="job-probe-gateway-1",
        cidr="192.168.10.0/24",
        status=DiscoveryJobStatus.PENDING,
        summary_json={
            "hosts": [{"ip": "192.168.10.2", "hostname": None, "ports": [53], "services": []}],
            "port_scan_stats": {
                "host_count": 1,
                "open_port_count": 1,
                "scanned_port_count": 1024,
                "service_probe_target_count": 1,
            },
        },
    )
    asset = Asset(id="asset-gateway-1", ip="192.168.10.2")
    asset.ports = [AssetPort(asset_id=asset.id, port=53, protocol="tcp", state="open", fingerprint_json={})]
    db = _FakeDB(job, assets=[asset])

    class _FakeScanner:
        def __init__(self, config):
            self.config = config

        async def probe_known_open_ports(self, hosts):
            return [
                SimpleNamespace(
                    ip="192.168.10.2",
                    hostname=None,
                    ports=[53],
                    services=[
                        {
                            "port": 53,
                            "service": "dns",
                            "application_service": "dns",
                            "probe_method": "connect",
                            "service_aliases": ["dns"],
                        }
                    ],
                )
            ]

    class _FakeNmapEnricher:
        def __init__(self, *args, **kwargs):
            return None

        async def enrich_hosts(self, targets):
            return {}

    class _FakeNseEnricher:
        def __init__(self, *args, **kwargs):
            return None

        async def enrich_hosts(self, targets):
            return SimpleNamespace(by_host={}, error_count=0)

    class _FakeWebExposureScanner:
        def __init__(self, *args, **kwargs):
            return None

        async def enrich_hosts(self, hosts):
            return {}

    monkeypatch.setattr(discovery_tasks, "SessionLocal", _FakeSessionLocal(db))
    monkeypatch.setattr(discovery_tasks, "AsyncNetworkDiscovery", _FakeScanner)
    monkeypatch.setattr(discovery_tasks, "AsyncNmapServiceEnricher", _FakeNmapEnricher)
    monkeypatch.setattr(discovery_tasks, "AsyncNmapScriptEnricher", _FakeNseEnricher)
    monkeypatch.setattr(discovery_tasks, "AsyncWebExposureScanner", _FakeWebExposureScanner)
    monkeypatch.setattr(discovery_tasks, "select_nse_scripts_for_record", lambda record, include_vuln=True: [])

    result = discovery_tasks.probe_open_services("job-probe-gateway-1")

    assert result == "job-probe-gateway-1"
    assert asset.is_infrastructure_device is True
    assert asset.status.value == "online"
    assert asset.asset_category == "network_infrastructure"
    assert asset.device_role == "gateway_dns"
    assert asset.device_assessment_json["device_role"] == "gateway_dns"
    assert asset.identity_source == discovery_tasks.NETWORK_DISCOVERY_INFERRED_IDENTITY_SOURCE
    assert job.summary_json["hosts"][0]["device_assessment"]["device_role"] == "gateway_dns"


def test_infer_discovery_asset_labels_does_not_mark_mixed_workload_host_as_infrastructure() -> None:
    labels = discovery_tasks._infer_discovery_asset_labels(
        {
            "ip": "192.168.10.138",
            "ports": [22, 53, 80, 3306],
            "services": [
                {"port": 22, "service": "ssh", "service_aliases": ["ssh"]},
                {"port": 53, "service": "dns", "service_aliases": ["dns"]},
                {"port": 80, "service": "apache", "service_aliases": ["apache", "http"]},
                {"port": 3306, "service": "mysql", "service_aliases": ["mysql"]},
            ],
        },
        cidr="192.168.10.0/24",
    )

    assert labels["asset_category"] == "general_endpoint"
    assert labels["device_role"] is None
    assert labels["is_infrastructure_device"] is False
    assert labels["device_assessment_json"]["asset_category"] == "general_endpoint"


def test_refresh_hostnames_from_web_exposure_metadata() -> None:
    hosts = [
        {
            "ip": "192.168.10.88",
            "hostname": None,
            "services": [
                {
                    "port": 443,
                    "service": "https",
                    "web": {"hostname_hint": "app.lab.local"},
                }
            ],
        }
    ]

    discovery_tasks._refresh_hostnames_from_services(hosts)

    assert hosts[0]["hostname"] == "app.lab.local"


def test_apply_network_initial_asset_status_marks_partial_snapshot_online() -> None:
    asset = Asset(id="asset-status-1", ip="192.168.10.10", status="collecting")
    snapshot = SimpleNamespace(collection_status="partial")

    discovery_tasks._apply_network_initial_asset_status(asset, snapshot)

    assert asset.status.value == "online"


def test_build_nmap_targets_forces_key_ports_and_rpcbind_related_unknown_high_ports() -> None:
    targets, low_confidence_count, nmap_skipped_count, backdoor_nmap_blocked_count = discovery_tasks._build_nmap_targets(
        [
            {
                "ip": "192.168.10.88",
                "services": [
                    {
                        "port": 21,
                        "service": "vsftpd",
                        "product_name": "vsftpd",
                        "product_version": "2.3.4",
                        "banner": "220 (vsFTPd 2.3.4)",
                    },
                    {
                        "port": 111,
                        "service": "rpcbind",
                        "product_name": "rpcbind",
                    },
                    {
                        "port": 33847,
                        "service": "unknown",
                    },
                ],
            }
        ],
        high_backdoor_ports={6667, 31337},
        threshold=70,
    )

    assert targets == [{"ip": "192.168.10.88", "ports": [21, 111, 33847]}]
    assert low_confidence_count == 3
    assert nmap_skipped_count == 0
    assert backdoor_nmap_blocked_count == 0
