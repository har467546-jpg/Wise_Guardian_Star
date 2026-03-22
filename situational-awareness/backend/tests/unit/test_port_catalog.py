from app.scanner.port_catalog import load_top_tcp_ports, resolve_scan_ports


def test_load_top_tcp_ports_parses_frequency_sorted_file(tmp_path) -> None:
    path = tmp_path / "nmap-services"
    path.write_text(
        """# comment
ssh\t22/tcp\t0.9
http\t80/tcp\t0.8
https\t443/tcp\t0.7
domain\t53/udp\t0.95
""",
        encoding="utf-8",
    )

    ports = load_top_tcp_ports(2, str(path))

    assert ports == (22, 80)


def test_resolve_scan_ports_merges_top_ports_and_custom(monkeypatch) -> None:
    monkeypatch.setattr("app.scanner.port_catalog.load_top_tcp_ports", lambda limit: (21, 22, 80))

    ports = resolve_scan_ports(
        curated_ports=(443, 3306),
        high_backdoor_ports=(31337,),
        mode="top1000_plus_custom",
        top_ports_limit=1000,
    )

    assert ports == (21, 22, 80, 443, 3306, 31337)
