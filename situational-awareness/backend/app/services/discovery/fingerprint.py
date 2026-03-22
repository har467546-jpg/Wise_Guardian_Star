from dataclasses import dataclass


@dataclass(slots=True)
class ServiceFingerprint:
    service: str
    version: str | None = None


COMMON_PORT_MAP: dict[int, str] = {
    22: "ssh",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
}


def identify_service(port: int, banner: str | None = None) -> ServiceFingerprint:
    service = COMMON_PORT_MAP.get(port, "unknown")
    version = None
    if banner:
        lower = banner.lower()
        if "openssh" in lower:
            service = "ssh"
            version = banner.strip()
        elif "nginx" in lower:
            service = "http"
            version = banner.strip()
        elif "apache" in lower:
            service = "http"
            version = banner.strip()
    return ServiceFingerprint(service=service, version=version)
