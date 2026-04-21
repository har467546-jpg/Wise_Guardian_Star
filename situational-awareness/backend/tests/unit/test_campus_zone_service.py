from datetime import datetime, timezone
from types import SimpleNamespace

from app.services import campus_zone_service


class _FakeDB:
    def __init__(self, zones):
        self.zones = list(zones)

    def scalars(self, stmt):  # noqa: ARG002
        class _Result:
            def __init__(self, items):
                self._items = items

            def all(self):
                return list(self._items)

        return _Result(self.zones)

    def get(self, model, object_id):  # noqa: ARG002
        for zone in self.zones:
            if zone.id == object_id:
                return zone
        return None


def test_find_matching_scanner_zones_matches_overlap() -> None:
    zones = [
        SimpleNamespace(id="zone-a", name="办公区", enabled=True, priority=10, cidrs_json=["10.10.0.0/24"]),
        SimpleNamespace(id="zone-b", name="宿舍区", enabled=True, priority=20, cidrs_json=["10.20.0.0/24"]),
    ]

    matched = campus_zone_service.find_matching_scanner_zones(_FakeDB(zones), "10.10.0.128/25")

    assert [item.id for item in matched] == ["zone-a"]


def test_choose_scanner_node_for_zone_prefers_online_runner() -> None:
    zone = SimpleNamespace(id="zone-a", name="办公区")
    offline = SimpleNamespace(
        id="assign-1",
        enabled=True,
        priority=50,
        visible_cidrs_json=[],
        asset=SimpleNamespace(host_runner=SimpleNamespace(install_status="installed", status="offline", last_seen_at=datetime.now(timezone.utc))),
        asset_id="asset-1",
    )
    online = SimpleNamespace(
        id="assign-2",
        enabled=True,
        priority=10,
        visible_cidrs_json=["10.10.0.0/24"],
        asset=SimpleNamespace(host_runner=SimpleNamespace(install_status="installed", status="online", last_seen_at=datetime.now(timezone.utc))),
        asset_id="asset-2",
    )

    service_db = _FakeDB([])

    original = campus_zone_service.list_scanner_node_assignments
    campus_zone_service.list_scanner_node_assignments = lambda db, zone_id: [offline, online]  # type: ignore[assignment]
    try:
        matched = campus_zone_service.choose_scanner_node_for_zone(service_db, zone=zone, target_cidr="10.10.0.5/32")
    finally:
        campus_zone_service.list_scanner_node_assignments = original  # type: ignore[assignment]

    assert matched is online


def test_choose_scanner_node_for_zone_skips_stale_runner() -> None:
    zone = SimpleNamespace(id="zone-a", name="办公区")
    stale = SimpleNamespace(
        id="assign-1",
        enabled=True,
        priority=10,
        visible_cidrs_json=["10.10.0.0/24"],
        asset=SimpleNamespace(
            host_runner=SimpleNamespace(
                install_status="installed",
                status="online",
                last_seen_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
        ),
        asset_id="asset-1",
    )

    service_db = _FakeDB([])

    original = campus_zone_service.list_scanner_node_assignments
    campus_zone_service.list_scanner_node_assignments = lambda db, zone_id: [stale]  # type: ignore[assignment]
    try:
        matched = campus_zone_service.choose_scanner_node_for_zone(service_db, zone=zone, target_cidr="10.10.0.5/32")
    finally:
        campus_zone_service.list_scanner_node_assignments = original  # type: ignore[assignment]

    assert matched is None
