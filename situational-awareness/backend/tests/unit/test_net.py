from app.utils.net import normalize_cidr


def test_normalize_cidr() -> None:
    assert normalize_cidr("192.168.1.2/24") == "192.168.1.0/24"
