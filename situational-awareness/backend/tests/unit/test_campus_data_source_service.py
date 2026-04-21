from datetime import datetime, timezone

from app.services import campus_data_source_service as campus_data_source


def test_parse_dnsmasq_leases_returns_observations() -> None:
    observations = campus_data_source.collect_dhcp_lease_observations(
        {"lease_file_path": ""},
        zone_name="宿舍区A",
    )

    assert observations == []


def test_parse_dnsmasq_payload_normalizes_mac_and_hostname() -> None:
    payload = "1713600000 7a:11:22:33:44:55 10.10.0.15 student-phone *\n"

    observations = campus_data_source._parse_dnsmasq_leases(payload, zone_name="宿舍区A")

    assert len(observations) == 1
    assert observations[0].mac_address == "7a:11:22:33:44:55"
    assert observations[0].hostname == "student-phone"
    assert observations[0].network_zone == "宿舍区A"


def test_normalize_mac_address_handles_dash_and_space_formats() -> None:
    assert campus_data_source.normalize_mac_address("00-50-56-C0-00-08") == "00:50:56:c0:00:08"
    assert campus_data_source.normalize_mac_address("00 50 56 C0 00 08") == "00:50:56:c0:00:08"


def test_is_locally_administered_mac_detects_randomized_prefix() -> None:
    assert campus_data_source.is_locally_administered_mac("7a:11:22:33:44:55") is True
    assert campus_data_source.is_locally_administered_mac("00:50:56:c0:00:08") is False


def test_observations_within_window_uses_30_minute_guardrail() -> None:
    left = datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc)
    right = datetime(2026, 4, 20, 8, 25, tzinfo=timezone.utc)
    far = datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc)

    assert campus_data_source.observations_within_window(left, right, window_seconds=1800) is True
    assert campus_data_source.observations_within_window(left, far, window_seconds=1800) is False
