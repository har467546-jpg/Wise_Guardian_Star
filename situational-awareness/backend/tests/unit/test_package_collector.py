from app.collector.package_collector import PACKAGE_COLLECTION_PLANS, parse_packages


def test_parse_dpkg_packages() -> None:
    raw = "bash\t5.2.15-2\tamd64\ncurl\t8.5.0\tamd64\n"
    parsed = parse_packages("dpkg", raw)
    assert parsed[0]["name"] == "bash"
    assert parsed[0]["version"] == "5.2.15-2"
    assert parsed[0]["manager"] == "dpkg"


def test_parse_rpm_packages() -> None:
    raw = "openssl\t3.0.7-28.el9\tx86_64\n"
    parsed = parse_packages("rpm", raw)
    assert parsed[0]["name"] == "openssl"
    assert parsed[0]["arch"] == "x86_64"


def test_parse_apk_packages() -> None:
    raw = "busybox-1.36.1-r21\n"
    parsed = parse_packages("apk", raw)
    assert parsed[0]["name"] == "busybox"
    assert parsed[0]["version"] == "1.36.1-r21"


def test_package_plan_priority() -> None:
    assert [plan.manager for plan in PACKAGE_COLLECTION_PLANS] == ["dpkg", "rpm", "apk"]
