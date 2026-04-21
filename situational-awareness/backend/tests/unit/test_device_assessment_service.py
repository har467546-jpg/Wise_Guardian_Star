from app.db.models.asset import Asset
from app.services.device_assessment_service import (
    apply_device_assessment_to_asset,
    build_discovery_host_device_assessment,
)


def test_discovery_device_assessment_identifies_gateway_dns_with_management_port() -> None:
    assessment = build_discovery_host_device_assessment(
        {
            "ip": "172.16.27.1",
            "ports": [22, 53],
            "services": [
                {"port": 22, "service": "ssh", "service_aliases": ["ssh"]},
                {"port": 53, "service": "dns", "service_aliases": ["dns"]},
            ],
        },
        cidr="172.16.27.0/24",
    )

    assert assessment is not None
    assert assessment["asset_category"] == "network_infrastructure"
    assert assessment["device_role"] == "gateway_dns"
    assert "gateway_candidate" in assessment["matched_traits"]


def test_discovery_device_assessment_marks_mixed_workload_as_general_endpoint() -> None:
    assessment = build_discovery_host_device_assessment(
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

    assert assessment is not None
    assert assessment["asset_category"] == "general_endpoint"
    assert assessment["device_role"] is None
    assert assessment["flags"]["is_infrastructure_device"] is False


def test_apply_device_assessment_keeps_higher_confidence_existing_result() -> None:
    asset = Asset(id="asset-1", ip="192.168.10.2")
    apply_device_assessment_to_asset(
        asset,
        {
            "asset_category": "network_infrastructure",
            "device_role": "gateway_dns",
            "assessment_source": "network_discovery",
            "confidence": 96,
            "matched_traits": ["gateway_candidate", "dns_signal"],
            "reasons": ["高置信度发现结果"],
            "flags": {
                "is_infrastructure_device": True,
                "is_iot": False,
                "is_virtual_network_component": False,
            },
            "evidence": {"open_ports": [53]},
        },
    )

    selected = apply_device_assessment_to_asset(
        asset,
        {
            "asset_category": "general_endpoint",
            "device_role": None,
            "assessment_source": "campus_observation",
            "confidence": 42,
            "matched_traits": [],
            "reasons": ["低置信度回填"],
            "flags": {
                "is_infrastructure_device": False,
                "is_iot": False,
                "is_virtual_network_component": False,
            },
            "evidence": {},
        },
    )

    assert selected is not None
    assert selected["asset_category"] == "network_infrastructure"
    assert asset.device_role == "gateway_dns"

