from app.collector.system_info import parse_cpu, parse_memory, parse_os_release, parse_running_services


def test_parse_os_release() -> None:
    raw = 'NAME="Ubuntu"\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
    parsed = parse_os_release(raw)
    assert parsed["name"] == "Ubuntu"
    assert parsed["version"] == "22.04"
    assert parsed["pretty_name"] == "Ubuntu 22.04.4 LTS"


def test_parse_cpu_from_lscpu() -> None:
    raw = (
        "Architecture:        x86_64\n"
        "CPU(s):              8\n"
        "Model name:          Intel(R) Xeon(R)\n"
        "Socket(s):           1\n"
        "Core(s) per socket:  4\n"
    )
    parsed = parse_cpu(raw)
    assert parsed["architecture"] == "x86_64"
    assert parsed["model"] == "Intel(R) Xeon(R)"
    assert parsed["cores"] == 4
    assert parsed["threads"] == 8


def test_parse_memory_from_free() -> None:
    raw = (
        "              total        used        free      shared  buff/cache   available\n"
        "Mem:      16777216     4194304     2097152      262144    10485760    12582912\n"
    )
    parsed = parse_memory(raw)
    assert parsed["total_bytes"] == 16777216
    assert parsed["available_bytes"] == 12582912


def test_parse_running_services_with_fallback() -> None:
    raw = "[ + ]  ssh\n[ - ]  apache2\n"
    parsed = parse_running_services(raw, fallback=True)
    assert parsed == [{"name": "ssh", "state": "running", "enabled": None, "pid": None}]
