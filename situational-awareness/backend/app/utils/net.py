import ipaddress


def normalize_cidr(raw: str) -> str:
    return str(ipaddress.ip_network(raw, strict=False))
