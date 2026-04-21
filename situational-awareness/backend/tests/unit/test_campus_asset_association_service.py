from datetime import datetime, timezone

from app.db.models.asset import Asset
from app.services import campus_asset_association_service as campus_association
from app.services.campus_data_source_service import CampusObservation


class _FakeDB:
    def __init__(self, assets, *, scalar_value=None):
        self.assets = list(assets)
        self.scalar_value = scalar_value

    def scalars(self, stmt):  # noqa: ARG002 - select is not executed in the fake
        class _Result:
            def __init__(self, items):
                self._items = items

            def all(self):
                return list(self._items)

        return _Result(self.assets)

    def scalar(self, stmt):  # noqa: ARG002 - select is not executed in the fake
        where_text = str(stmt).split("WHERE", 1)[-1]
        if self.scalar_value is None:
            return None
        if "assets.network_zone" in where_text or "assets.hostname" in where_text:
            return None
        return self.scalar_value

    def add(self, item):  # noqa: ARG002
        return None

    def flush(self):
        return None


def test_same_mac_requires_same_zone_or_vlan() -> None:
    candidate = Asset(ip="10.10.0.15")
    candidate.mac_address = "7a:11:22:33:44:55"
    candidate.network_zone = "宿舍A"
    candidate.network_vlan = "vlan-100"
    candidate.last_auth_time = datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc)
    candidate.last_seen_at = datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc)
    db = _FakeDB([candidate], scalar_value=None)

    observation = CampusObservation(
        source_type="dhcp_lease",
        observed_at=datetime(2026, 4, 20, 8, 5, tzinfo=timezone.utc),
        ip="10.20.0.15",
        mac_address="7a:11:22:33:44:55",
        network_zone="宿舍B",
        network_vlan="vlan-200",
    )

    decision = campus_association.find_asset_for_observation(db, observation)

    assert decision.asset is None
    assert decision.match_reason == "new_asset"


def test_random_mac_only_merges_inside_time_window() -> None:
    candidate = Asset(ip="10.10.0.15")
    candidate.mac_address = "7a:11:22:33:44:55"
    candidate.network_zone = "宿舍A"
    candidate.network_vlan = "vlan-100"
    candidate.last_auth_time = datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc)
    candidate.last_seen_at = datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc)
    db = _FakeDB([candidate], scalar_value=None)

    observation = CampusObservation(
        source_type="dhcp_lease",
        observed_at=datetime(2026, 4, 20, 8, 10, tzinfo=timezone.utc),
        ip="10.10.0.15",
        mac_address="7a:11:22:33:44:55",
        hostname="student-phone",
        network_zone="宿舍A",
        network_vlan="vlan-100",
    )

    decision = campus_association.find_asset_for_observation(db, observation)

    assert decision.asset is candidate
    assert decision.match_reason == "mac+zone_time_window"


def test_active_scan_can_reuse_same_ip_outside_time_window() -> None:
    candidate = Asset(ip="10.10.0.15")
    candidate.network_zone = None
    candidate.last_auth_time = None
    candidate.last_seen_at = datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc)
    db = _FakeDB([], scalar_value=candidate)

    observation = CampusObservation(
        source_type="active_scan",
        observed_at=datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc),
        ip="10.10.0.15",
        network_zone="宿舍A",
    )

    decision = campus_association.find_asset_for_observation(db, observation)

    assert decision.asset is candidate
    assert decision.match_reason == "ip_active_scan_fallback"
