from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

DEFAULT_SERVICE_BY_PORT: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2121: "ftp",
    2375: "docker",
    2376: "docker-tls",
    3000: "http",
    3306: "mysql",
    3632: "distccd",
    3389: "rdp",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "kubernetes-api",
    6667: "irc",
    7001: "weblogic",
    8000: "http",
    8009: "ajp13",
    8080: "http",
    8081: "http",
    8180: "http",
    8443: "https",
    9000: "http",
    9090: "prometheus",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    11211: "memcached",
    1099: "java-rmi",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    27017: "mongodb",
}

SSH_PRODUCT_RE = re.compile(r"^SSH-\d+\.\d+-(?P<product>[^\r\n]+)", re.IGNORECASE)
HTTP_SERVER_RE = re.compile(r"^Server:\s*(?P<server>[^\r\n]+)", re.IGNORECASE | re.MULTILINE)
HTTP_LOCATION_RE = re.compile(r"^Location:\s*(?P<location>[^\r\n]+)", re.IGNORECASE | re.MULTILINE)
HTTP_TITLE_RE = re.compile(r"<title>\s*(?P<title>[^<]+)\s*</title>", re.IGNORECASE)
KIBANA_VERSION_RE = re.compile(r"^kbn-version:\s*(?P<version>[^\r\n]+)", re.IGNORECASE | re.MULTILINE)
API_VERSION_RE = re.compile(r"^Api-Version:\s*(?P<version>[^\r\n]+)", re.IGNORECASE | re.MULTILINE)
VERSION_RE = re.compile(r"(?P<version>\d+(?:\.\d+){1,3})")
MYSQL_VERSION_RE = re.compile(r"\x0a(?P<version>\d+(?:\.\d+){1,3}[^\x00]*)\x00")
HOSTNAME_RE = re.compile(r"\b(?P<hostname>[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b")
SMTP_PRODUCT_RE = re.compile(r"\b(postfix|exim|sendmail|exchange)\b", re.IGNORECASE)
FTP_PRODUCT_RE = re.compile(r"\b(vsftpd|proftpd|pure-ftpd|filezilla(?: server)?|wu-ftpd|bftpd)\b", re.IGNORECASE)
FTP_HINT_RE = re.compile(r"\b(vsftpd|proftpd|pure-ftpd|filezilla|wu-ftpd|bftpd|ftp server|ftpd|ftp)\b", re.IGNORECASE)
APACHE_VERSION_RE = re.compile(r"\bapache(?:/|[- ]httpd/)(?P<version>\d+(?:\.\d+){1,3})", re.IGNORECASE)
PHP_VERSION_RE = re.compile(r"\bphp/(?P<version>\d+(?:\.\d+){1,3})", re.IGNORECASE)
TOMCAT_VERSION_RE = re.compile(r"\bapache tomcat/(?P<version>\d+(?:\.\d+){1,3})", re.IGNORECASE)
VSFTPD_VERSION_RE = re.compile(r"\bvsftpd[ /](?P<version>\d+(?:\.\d+){1,3})", re.IGNORECASE)
OPENSSH_VERSION_RE = re.compile(r"\bopenssh[_/-](?P<version>\d+(?:\.\d+){1,3})", re.IGNORECASE)
UNREALIRCD_VERSION_RE = re.compile(r"\bunrealircd[ /-](?P<version>\d+(?:\.\d+){1,3}(?:\.\d+)?)", re.IGNORECASE)
DISTCCD_VERSION_RE = re.compile(r"\bdistccd?[ /-](?P<version>\d+(?:\.\d+){1,3})", re.IGNORECASE)
HTTP_PRODUCT_PATTERNS: tuple[tuple[re.Pattern[str], tuple[str, str]], ...] = (
    (re.compile(r"\bphpmyadmin\b", re.IGNORECASE), ("phpmyadmin", "phpmyadmin")),
    (re.compile(r"\btwiki\b", re.IGNORECASE), ("twiki", "twiki")),
    (re.compile(r"\bopenresty\b", re.IGNORECASE), ("nginx", "openresty")),
    (re.compile(r"\bnginx\b", re.IGNORECASE), ("nginx", "nginx")),
    (re.compile(r"\bapache[- ]coyote\b|\btomcat\b|\bcoyote jsp\b", re.IGNORECASE), ("tomcat", "tomcat")),
    (re.compile(r"\bapache\b|\bhttpd\b", re.IGNORECASE), ("apache", "apache")),
    (re.compile(r"\bkibana\b", re.IGNORECASE), ("kibana", "kibana")),
    (re.compile(r"\belasticsearch\b", re.IGNORECASE), ("elasticsearch", "elasticsearch")),
    (re.compile(r"\bdocker\b", re.IGNORECASE), ("docker", "docker")),
)


@dataclass(frozen=True, slots=True)
class InferredFingerprint:
    transport_service: str | None = None
    application_service: str | None = None
    product_name: str | None = None
    product_version: str | None = None


@dataclass(slots=True)
class ServiceFingerprint:
    port: int
    service: str
    banner: str | None
    version: str | None = None
    hostname_hint: str | None = None
    probe_method: str = "connect"
    transport_service: str | None = None
    application_service: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    tls_detected: bool = False
    evidence: list[str] = field(default_factory=list)
    probe_chain: list[str] = field(default_factory=list)
    nmap_service: str | None = None
    nmap_product: str | None = None
    service_aliases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, str | int | bool | list[str] | None]:
        return {
            "port": self.port,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "hostname_hint": self.hostname_hint,
            "probe_method": self.probe_method,
            "transport_service": self.transport_service,
            "application_service": self.application_service,
            "product_name": self.product_name,
            "product_version": self.product_version,
            "tls_detected": self.tls_detected,
            "evidence": list(self.evidence),
            "probe_chain": list(self.probe_chain),
            "nmap_service": self.nmap_service,
            "nmap_product": self.nmap_product,
            "service_aliases": list(self.service_aliases),
        }


def fingerprint_service(
    port: int,
    banner: str | None,
    certificate_names: list[str] | None = None,
    probe_method: str = "connect",
    *,
    transport_service: str | None = None,
    application_service: str | None = None,
    product_name: str | None = None,
    product_version: str | None = None,
    tls_detected: bool = False,
    evidence: list[str] | None = None,
    probe_chain: list[str] | None = None,
    nmap_service: str | None = None,
    nmap_product: str | None = None,
) -> ServiceFingerprint:
    banner = banner or ""
    certificate_names = certificate_names or []
    default_service = DEFAULT_SERVICE_BY_PORT.get(port, "unknown")

    hostname_hint = _pick_hostname(certificate_names)
    if not hostname_hint:
        hostname_hint = _extract_http_location_host(banner)
    if not hostname_hint:
        hostname_hint = _extract_banner_hostname(banner)

    inferred = _infer_from_banner(
        port=port,
        banner=banner,
        certificate_names=certificate_names,
        tls_detected=tls_detected,
    )
    http_like_banner = banner.startswith("HTTP/") or HTTP_SERVER_RE.search(banner) is not None

    resolved_transport = _normalize_service_label(
        transport_service
        or inferred.transport_service
        or ("https" if (tls_detected or certificate_names) and default_service == "http" else default_service)
    )
    resolved_product_name = _normalize_product_name(product_name or inferred.product_name or nmap_product)
    resolved_application = normalize_application_service(
        application_service or inferred.application_service or resolved_product_name or resolved_transport,
        transport_service=resolved_transport,
        product_name=resolved_product_name,
        port=port,
    )
    resolved_version = product_version or inferred.product_version or (None if http_like_banner else _normalize_version(banner))
    resolved_service = resolved_application or resolved_transport or default_service
    service_aliases = infer_service_aliases(
        {
            "port": port,
            "service": resolved_service,
            "transport_service": resolved_transport,
            "application_service": resolved_application,
            "product_name": resolved_product_name,
            "product_version": resolved_version,
            "version": resolved_version,
            "banner": banner,
            "tls_detected": bool(tls_detected or certificate_names),
            "nmap_service": nmap_service,
            "nmap_product": nmap_product,
        }
    )

    return ServiceFingerprint(
        port=port,
        service=resolved_service,
        banner=banner.strip() or None,
        version=resolved_version,
        hostname_hint=hostname_hint,
        probe_method=probe_method,
        transport_service=resolved_transport,
        application_service=resolved_application,
        product_name=resolved_product_name,
        product_version=resolved_version,
        tls_detected=bool(tls_detected or certificate_names or resolved_transport in {"https", "smtps", "pop3s", "imaps"}),
        evidence=list(dict.fromkeys([item for item in (evidence or []) if isinstance(item, str) and item.strip()])),
        probe_chain=list(dict.fromkeys([item for item in (probe_chain or []) if isinstance(item, str) and item.strip()])),
        nmap_service=_normalize_service_label(nmap_service) if nmap_service else None,
        nmap_product=_normalize_product_name(nmap_product) if nmap_product else None,
        service_aliases=service_aliases,
    )


SERVICE_ALIAS_PRIORITY: tuple[str, ...] = (
    "vsftpd",
    "ftp",
    "ssh",
    "samba",
    "rpcbind",
    "unrealircd",
    "irc",
    "distccd",
    "java-rmi",
    "ajp13",
    "rexec",
    "rlogin",
    "rsh",
    "phpmyadmin",
    "twiki",
    "tomcat",
    "apache",
    "nginx",
    "php",
    "http",
    "https",
    "mysql",
    "postgresql",
    "redis",
    "bind",
    "smtp",
    "pop3",
    "imap",
    "telnet",
)


def infer_service_aliases(record: dict[str, object] | None) -> list[str]:
    if not isinstance(record, dict):
        return []

    aliases: set[str] = set()
    ordered: list[str] = []

    def _add(alias: str | None) -> None:
        normalized = _normalize_service_label(alias)
        if normalized == "unknown" or normalized in aliases:
            return
        aliases.add(normalized)
        ordered.append(normalized)

    port = _to_port(record.get("port"))
    default_service = DEFAULT_SERVICE_BY_PORT.get(port, "unknown")
    banner = str(record.get("banner") or "")
    version = str(record.get("version") or record.get("product_version") or record.get("service_version") or "")
    combined = f"{banner}\n{version}".lower()
    nse = record.get("nse") if isinstance(record.get("nse"), dict) else {}
    tls_detected = bool(record.get("tls_detected") is True)
    tomcat_marker = "apache-coyote" in combined or "apache tomcat" in combined or "tomcat" in combined

    for key in ("application_service", "product_name", "service", "service_name", "transport_service", "nmap_product", "nmap_service"):
        _add(str(record.get(key) or ""))

    if "vsftpd" in combined:
        _add("vsftpd")
    if "openssh" in combined:
        _add("ssh")
    if "samba" in combined or "smbd" in combined:
        _add("samba")
    if "unrealircd" in combined:
        _add("unrealircd")
        _add("irc")
    elif port == 6667 and ("notice auth" in combined or "privmsg" in combined or "irc." in combined):
        _add("irc")
    if "distcc" in combined:
        _add("distccd")
    if "java rmi" in combined or "rmiregistry" in combined or "unicastref" in combined:
        _add("java-rmi")
    if "ajp" in combined or "ajp13" in combined:
        _add("ajp13")
    if port == 512:
        _add("rexec")
    if port == 513:
        _add("rlogin")
    if port == 514:
        _add("rsh")
    if tomcat_marker:
        _add("tomcat")
    if ("apache" in combined or "httpd" in combined) and not tomcat_marker:
        _add("apache")
    if "nginx" in combined or "openresty" in combined:
        _add("nginx")
    if "phpmyadmin" in combined:
        _add("phpmyadmin")
    if "twiki" in combined:
        _add("twiki")
    if "x-powered-by: php/" in combined or "\nphp/" in combined or combined.startswith("php/"):
        _add("php")
    if "postgresql" in combined or "postgres" in combined:
        _add("postgresql")
    if "mysql" in combined or "mariadb" in combined:
        _add("mysql")
    if "redis" in combined:
        _add("redis")
    if "bind" in combined or "named" in combined:
        _add("bind")
    if "rpcbind" in combined or "portmapper" in combined:
        _add("rpcbind")

    http_title = nse.get("http-title")
    if isinstance(http_title, dict):
        title = str(http_title.get("title") or "").lower()
        if "apache tomcat" in title:
            _add("tomcat")
        if "phpmyadmin" in title:
            _add("phpmyadmin")
        if "twiki" in title:
            _add("twiki")

    http_headers = nse.get("http-headers")
    if isinstance(http_headers, dict):
        headers = http_headers.get("headers")
        if isinstance(headers, dict):
            server = str(headers.get("server") or "").lower()
            powered_by = str(headers.get("x-powered-by") or "").lower()
            server_is_tomcat = "apache-coyote" in server or "tomcat" in server
            if server_is_tomcat:
                _add("tomcat")
            if ("apache" in server or "httpd" in server) and not server_is_tomcat:
                _add("apache")
            if "nginx" in server:
                _add("nginx")
            if "php/" in powered_by:
                _add("php")

    http_enum = nse.get("http-enum")
    if isinstance(http_enum, dict):
        discovered_paths = http_enum.get("discovered_paths")
        if isinstance(discovered_paths, list):
            lower_paths = {str(item).lower() for item in discovered_paths if isinstance(item, str)}
            if any("/manager/html" in item for item in lower_paths):
                _add("tomcat")
            if any("/phpmyadmin" in item for item in lower_paths):
                _add("phpmyadmin")
            if any("/twiki" in item for item in lower_paths):
                _add("twiki")

    if "vsftpd" in aliases:
        _add("ftp")
    if any(alias in aliases for alias in {"apache", "nginx", "tomcat", "php", "phpmyadmin", "twiki"}):
        _add("https" if tls_detected else "http")
    if "phpmyadmin" in aliases:
        _add("php")
    if "unrealircd" in aliases:
        _add("irc")

    if not ordered and default_service != "unknown":
        _add(default_service)

    priority = {name: index for index, name in enumerate(SERVICE_ALIAS_PRIORITY)}
    return sorted(
        ordered,
        key=lambda item: (priority.get(item, len(priority)), ordered.index(item)),
    )


def infer_service_versions(record: dict[str, object] | None) -> dict[str, str]:
    if not isinstance(record, dict):
        return {}

    versions: dict[str, str] = {}

    def _set(alias: str, value: str | None) -> None:
        normalized_alias = _normalize_service_label(alias)
        normalized_value = _normalize_version(value)
        if normalized_alias == "unknown" or not normalized_value or normalized_alias in versions:
            return
        versions[normalized_alias] = normalized_value

    banner = str(record.get("banner") or "")
    combined = "\n".join(
        [
            banner,
            str(record.get("product_version") or ""),
            str(record.get("version") or ""),
            str(record.get("service_version") or ""),
            str(record.get("nmap_product") or ""),
            str(record.get("nmap_service") or ""),
        ]
    )

    primary_aliases = infer_service_aliases(record)
    direct_version = _normalize_version(
        str(record.get("product_version") or record.get("version") or record.get("service_version") or "")
    )
    if direct_version and primary_aliases:
        _set(primary_aliases[0], direct_version)

    for alias, pattern in (
        ("vsftpd", VSFTPD_VERSION_RE),
        ("ssh", OPENSSH_VERSION_RE),
        ("apache", APACHE_VERSION_RE),
        ("php", PHP_VERSION_RE),
        ("tomcat", TOMCAT_VERSION_RE),
        ("unrealircd", UNREALIRCD_VERSION_RE),
        ("distccd", DISTCCD_VERSION_RE),
    ):
        match = pattern.search(combined)
        if match:
            _set(alias, match.group("version"))

    nse = record.get("nse") if isinstance(record.get("nse"), dict) else {}
    http_title = nse.get("http-title")
    if isinstance(http_title, dict):
        title = str(http_title.get("title") or "")
        tomcat_match = TOMCAT_VERSION_RE.search(title)
        if tomcat_match:
            _set("tomcat", tomcat_match.group("version"))

    http_headers = nse.get("http-headers")
    if isinstance(http_headers, dict):
        headers = http_headers.get("headers")
        if isinstance(headers, dict):
            server = str(headers.get("server") or "")
            server_lower = server.lower()
            if "apache-coyote" not in server_lower and "tomcat" not in server_lower:
                _set("apache", server)
            _set("php", str(headers.get("x-powered-by") or ""))

    if "vsftpd" in versions and "ftp" not in versions:
        versions["ftp"] = versions["vsftpd"]
    if "unrealircd" in versions and "irc" not in versions:
        versions["irc"] = versions["unrealircd"]

    return versions


def normalize_application_service(
    value: str | None,
    *,
    transport_service: str | None,
    product_name: str | None,
    port: int,
) -> str:
    combined = " ".join(
        [
            _normalize_service_label(value),
            _normalize_product_name(product_name) or "",
            _normalize_service_label(transport_service),
        ]
    ).strip()

    if "phpmyadmin" in combined:
        return "phpmyadmin"
    if "twiki" in combined:
        return "twiki"
    if "openresty" in combined or "nginx" in combined:
        return "nginx"
    if "apache-coyote" in combined or "tomcat" in combined or "coyote jsp" in combined:
        return "tomcat"
    if "apache" in combined or "httpd" in combined:
        return "apache"
    if "openssh" in combined or combined == "ssh":
        return "ssh"
    if "postgres" in combined:
        return "postgresql"
    if "mysql" in combined or "mariadb" in combined:
        return "mysql"
    if "redis" in combined:
        return "redis"
    if "rpcbind" in combined or "portmapper" in combined:
        return "rpcbind"
    if "vsftpd" in combined or combined == "ftp":
        return "vsftpd" if "vsftpd" in combined else "ftp"
    if "samba" in combined or "smb" in combined:
        return "samba"
    if "distcc" in combined:
        return "distccd"
    if "unrealircd" in combined:
        return "unrealircd"
    if "java rmi" in combined or "java-rmi" in combined or "rmiregistry" in combined or "unicastref" in combined or combined == "java-rmi":
        return "java-rmi"
    if "ajp" in combined or combined == "ajp13":
        return "ajp13"
    if "rexec" in combined or port == 512:
        return "rexec"
    if "rlogin" in combined or port == 513:
        return "rlogin"
    if "rsh" in combined or port == 514:
        return "rsh"
    if "php " in combined or combined == "php":
        return "php"
    if "bind" in combined or "named" in combined:
        return "bind"
    if "kibana" in combined:
        return "kibana"
    if "elasticsearch" in combined:
        return "elasticsearch"
    if "docker" in combined:
        return "docker"
    if "memcached" in combined:
        return "memcached"
    if "smtp" in combined or port in {25, 465, 587}:
        return "smtp"
    if "pop3" in combined or port in {110, 995}:
        return "pop3"
    if "imap" in combined or port in {143, 993}:
        return "imap"
    if "telnet" in combined or port == 23:
        return "telnet"
    if transport_service:
        return _normalize_service_label(transport_service)
    return _normalize_service_label(value)


def _to_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _infer_from_banner(
    *,
    port: int,
    banner: str,
    certificate_names: list[str],
    tls_detected: bool,
) -> InferredFingerprint:
    normalized_banner = banner or ""
    if not normalized_banner:
        return InferredFingerprint()

    if normalized_banner.startswith("SSH-"):
        product = _search_group(SSH_PRODUCT_RE, normalized_banner, "product") or "ssh"
        return InferredFingerprint(
            transport_service="ssh",
            application_service="ssh",
            product_name=_normalize_product_name(product),
            product_version=_normalize_version(product or normalized_banner),
        )

    if "HTTP/" in normalized_banner or HTTP_SERVER_RE.search(normalized_banner):
        return _infer_http_fingerprint(port, normalized_banner, certificate_names, tls_detected)

    if normalized_banner.startswith("+PONG") or normalized_banner.startswith("-NOAUTH") or normalized_banner.startswith("-ERR"):
        return InferredFingerprint(
            transport_service="redis",
            application_service="redis",
            product_name="redis",
            product_version=_normalize_version(normalized_banner),
        )

    mysql_version = _search_group(MYSQL_VERSION_RE, normalized_banner, "version")
    if mysql_version or port == 3306:
        return InferredFingerprint(
            transport_service="mysql",
            application_service="mysql",
            product_name="mysql",
            product_version=_normalize_version(mysql_version or normalized_banner),
        )

    if normalized_banner.startswith("VERSION "):
        return InferredFingerprint(
            transport_service="memcached",
            application_service="memcached",
            product_name="memcached",
            product_version=_normalize_version(normalized_banner),
        )

    if normalized_banner.startswith("+OK"):
        return InferredFingerprint(
            transport_service="pop3",
            application_service="pop3",
            product_name="pop3",
            product_version=_normalize_version(normalized_banner),
        )

    if normalized_banner.startswith("* OK"):
        return InferredFingerprint(
            transport_service="imap",
            application_service="imap",
            product_name="imap",
            product_version=_normalize_version(normalized_banner),
        )

    if normalized_banner.startswith("220") and (port == 21 or FTP_HINT_RE.search(normalized_banner)):
        product_match = _search_group(FTP_PRODUCT_RE, normalized_banner, 0)
        normalized_product = _normalize_product_name(product_match or "ftp")
        application_service = "vsftpd" if normalized_product == "vsftpd" else "ftp"
        return InferredFingerprint(
            transport_service="ftp",
            application_service=application_service,
            product_name=normalized_product,
            product_version=_normalize_version(normalized_banner),
        )

    if normalized_banner.startswith("220"):
        product_match = _search_group(SMTP_PRODUCT_RE, normalized_banner, 0)
        return InferredFingerprint(
            transport_service="smtp",
            application_service="smtp",
            product_name=_normalize_product_name(product_match or "smtp"),
            product_version=_normalize_version(normalized_banner),
        )

    if "\xff" in normalized_banner or port == 23:
        return InferredFingerprint(
            transport_service="telnet",
            application_service="telnet",
            product_name="telnet",
            product_version=None,
        )

    return InferredFingerprint()


def _infer_http_fingerprint(
    port: int,
    banner: str,
    certificate_names: list[str],
    tls_detected: bool,
) -> InferredFingerprint:
    transport_service = "https" if tls_detected or certificate_names or port in {443, 8443, 6443, 2376} else "http"
    server = _search_group(HTTP_SERVER_RE, banner, "server") or ""
    title = _search_group(HTTP_TITLE_RE, banner, "title") or ""
    version = None
    body_product_name = None
    application_service = transport_service

    for pattern, mapped in HTTP_PRODUCT_PATTERNS:
        if pattern.search(server) or pattern.search(title) or pattern.search(banner):
            application_service, body_product_name = mapped
            break

    lower_banner = banner.lower()
    if '"tagline"' in lower_banner and "you know, for search" in lower_banner:
        application_service = "elasticsearch"
        body_product_name = "elasticsearch"
        json_version = _extract_json_version(banner)
        if json_version:
            version = json_version
    elif "kbn-name" in lower_banner or "kibana" in lower_banner:
        application_service = "kibana"
        body_product_name = "kibana"
        version = _search_group(KIBANA_VERSION_RE, banner, "version") or version
    elif "docker api" in lower_banner or "api-version:" in lower_banner:
        application_service = "docker"
        body_product_name = "docker"
        version = _search_group(API_VERSION_RE, banner, "version") or version

    version = version or _extract_http_version(server, banner, application_service=application_service)
    if application_service == "tomcat":
        version = _search_group(TOMCAT_VERSION_RE, title or banner, "version") or version
        if server.lower().startswith("apache-coyote/") and not _search_group(TOMCAT_VERSION_RE, title or banner, "version"):
            version = None
    if application_service in {"phpmyadmin", "twiki"}:
        version = None

    return InferredFingerprint(
        transport_service=transport_service,
        application_service=application_service,
        product_name=_normalize_product_name(body_product_name or application_service),
        product_version=_normalize_version(version),
    )


def _extract_http_version(server_header: str, banner: str, *, application_service: str | None = None) -> str | None:
    if server_header:
        header_lower = server_header.lower()
        if "apache-coyote/" in header_lower and application_service == "tomcat":
            return None
        if application_service in {"phpmyadmin", "twiki"}:
            return None
        return _normalize_version(server_header)
    if application_service in {"phpmyadmin", "twiki", "tomcat"}:
        return None
    return _normalize_version(banner)


def _extract_json_version(content: str) -> str | None:
    try:
        _, _, body = content.partition("\r\n\r\n")
        if not body:
            return None
        payload = json.loads(body)
    except Exception:
        return None
    version = payload.get("version")
    if isinstance(version, dict):
        number = version.get("number")
        if isinstance(number, str):
            return number
    return None


def _search_group(pattern: re.Pattern[str], content: str, group: str | int) -> str | None:
    match = pattern.search(content)
    if not match:
        return None
    value = match.group(group)
    return value.strip() if isinstance(value, str) else None


def _normalize_service_label(value: str | None) -> str:
    if not value:
        return "unknown"
    cleaned = value.strip().lower()
    return cleaned or "unknown"


def _normalize_product_name(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    if not cleaned:
        return None
    for token in ["(", "[", ";"]:
        if token in cleaned:
            cleaned = cleaned.split(token, 1)[0].strip()
    cleaned = cleaned.replace("/", " ").replace("_", " ")
    if cleaned.startswith("apache-coyote"):
        return "tomcat"
    if "openresty" in cleaned:
        return "openresty"
    if "nginx" in cleaned:
        return "nginx"
    if "apache" in cleaned or "httpd" in cleaned:
        return "apache"
    if "openssh" in cleaned:
        return "openssh"
    if "postgres" in cleaned:
        return "postgresql"
    if "mysql" in cleaned or "mariadb" in cleaned:
        return "mysql"
    if "redis" in cleaned:
        return "redis"
    if "rpcbind" in cleaned or "portmapper" in cleaned:
        return "rpcbind"
    if "memcached" in cleaned:
        return "memcached"
    if "docker" in cleaned:
        return "docker"
    if "kibana" in cleaned:
        return "kibana"
    if "elasticsearch" in cleaned:
        return "elasticsearch"
    if "phpmyadmin" in cleaned:
        return "phpmyadmin"
    if "twiki" in cleaned:
        return "twiki"
    if "java rmi" in cleaned or "java-rmi" in cleaned or "rmiregistry" in cleaned or "unicastref" in cleaned:
        return "java-rmi"
    if "ajp" in cleaned:
        return "ajp13"
    if "rexec" in cleaned:
        return "rexec"
    if "rlogin" in cleaned:
        return "rlogin"
    if "rsh" in cleaned:
        return "rsh"
    return cleaned.split()[0]


def _normalize_version(value: str | None) -> str | None:
    if not value:
        return None
    match = VERSION_RE.search(value)
    if not match:
        return None
    return match.group("version")


def _pick_hostname(certificate_names: list[str]) -> str | None:
    for name in certificate_names:
        candidate = name.strip().lower()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            return candidate
    return None


def _extract_http_location_host(banner: str) -> str | None:
    location = _search_group(HTTP_LOCATION_RE, banner, "location")
    if not location:
        return None
    parsed = urlparse(location)
    return parsed.hostname


def _extract_banner_hostname(banner: str) -> str | None:
    match = HOSTNAME_RE.search(banner)
    if not match:
        return None
    return match.group("hostname").lower()
