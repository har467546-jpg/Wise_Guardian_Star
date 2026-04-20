import ipaddress
from types import SimpleNamespace

from app.utils import net


def test_normalize_cidr() -> None:
    assert net.normalize_cidr("192.168.1.2/24") == "192.168.1.0/24"


def test_list_local_ipv4_interfaces_parses_ip_output(monkeypatch) -> None:
    monkeypatch.setattr(
        net.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                "1: lo    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0    inet 192.168.130.137/24 brd 192.168.130.255 scope global eth0\n"
                "3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n"
            ),
        ),
    )

    parsed = net.list_local_ipv4_interfaces()

    assert [item.name for item in parsed] == ["eth0", "docker0"]
    assert [item.ip for item in parsed] == ["192.168.130.137", "172.17.0.1"]


def test_find_local_ipv4_interface_for_network_prefers_most_specific_match(monkeypatch) -> None:
    monkeypatch.setattr(
        net,
        "list_local_ipv4_interfaces",
        lambda: [
            net.LocalIPv4Interface(name="eth0", interface=ipaddress.IPv4Interface("192.168.0.10/16")),
            net.LocalIPv4Interface(name="eth1", interface=ipaddress.IPv4Interface("192.168.130.10/24")),
        ],
    )

    matched = net.find_local_ipv4_interface_for_network("192.168.130.0/25")

    assert matched is not None
    assert matched.name == "eth1"
