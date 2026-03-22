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


def test_filter_excluded_local_hosts_skips_gateway_candidate(monkeypatch) -> None:
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

    assert filtered == [{"ip": "192.168.10.88", "hostname": "target-host"}]
    assert excluded == [{"ip": "192.168.10.254", "hostname": "gateway-host", "reason": "命中网段边界网关候选地址"}]


def test_discover_hosts_excludes_gateway_candidate(monkeypatch) -> None:
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
    assert job.summary_json["host_count"] == 1
    assert job.summary_json["hosts"] == [{"ip": "192.168.10.88", "hostname": "target-host", "ports": [], "services": []}]
    assert job.summary_json["excluded_local_ip_count"] == 1
    assert job.summary_json["excluded_local_hosts"] == [
        {"ip": "192.168.10.254", "hostname": "gateway-host", "reason": "命中网段边界网关候选地址"}
    ]
    assert db.committed is True


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
    assert db.executed
    assert job.summary_json["excluded_local_ip_count"] == 1
    assert job.summary_json["excluded_local_hosts"][0]["ip"] == "192.168.10.5"
    assert db.committed is True


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

    monkeypatch.setattr(discovery_tasks, "SessionLocal", _FakeSessionLocal(db))
    monkeypatch.setattr(discovery_tasks, "AsyncNetworkDiscovery", _FakeScanner)
    monkeypatch.setattr(discovery_tasks, "AsyncNmapServiceEnricher", _FakeNmapEnricher)
    monkeypatch.setattr(discovery_tasks, "AsyncNmapScriptEnricher", _FakeNseEnricher)
    monkeypatch.setattr(
        discovery_tasks,
        "select_nse_scripts_for_record",
        lambda record, include_vuln=True: ["ssh2-enum-algos"] if int(record.get("port") or 0) == 22 else ["http-title"],
    )

    result = discovery_tasks.probe_open_services("job-probe-1")

    assert result == "job-probe-1"
    assert captured["probe_hosts"] == [{"ip": "192.168.10.88", "hostname": "target-host", "ports": [22, 80], "services": []}]
    assert captured["nmap_targets"] == [{"ip": "192.168.10.88", "ports": [80]}]
    assert captured["nse_targets"] == [{"ip": "192.168.10.88", "ports": [22, 80], "scripts": ["http-title", "ssh2-enum-algos"], "port_scripts": {22: ["ssh2-enum-algos"], 80: ["http-title"]}}]
    assert job.summary_json["hosts"][0]["services"]
    assert job.summary_json["service_enrichment_stats"]["network_initial_snapshot_count"] == 1


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
