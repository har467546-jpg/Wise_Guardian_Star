from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ServiceConfigCollectionPlan:
    service: str
    command: str


SERVICE_CONFIG_COLLECTION_PLANS: dict[str, ServiceConfigCollectionPlan] = {
    "ssh": ServiceConfigCollectionPlan(
        service="ssh",
        command=(
            "sh -lc 'printf \"source_file=/etc/ssh/sshd_config\\n\"; "
            "(sshd -T 2>/dev/null | grep -Ei \"^(passwordauthentication|permitrootlogin|pubkeyauthentication|permitemptypasswords) \" "
            "|| grep -H -Eiv \"^[[:space:]]*(#|$)\" /etc/ssh/sshd_config 2>/dev/null "
            "| grep -Ei \"(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|PermitEmptyPasswords)[[:space:]]+\") || true'"
        ),
    ),
    "redis": ServiceConfigCollectionPlan(
        service="redis",
        command=(
            "sh -lc 'for f in /etc/redis/redis.conf /etc/redis.conf; do "
            "if [ -f \"$f\" ]; then "
            "grep -Eiv \"^[[:space:]]*(#|$)\" \"$f\" | grep -Ei \"^(bind|protected-mode|requirepass)[[:space:]]+\" || true; "
            "fi; done'"
        ),
    ),
    "vsftpd": ServiceConfigCollectionPlan(
        service="vsftpd",
        command=(
            "sh -lc 'for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do "
            "if [ -f \"$f\" ]; then "
            "grep -Eiv \"^[[:space:]]*(#|$)\" \"$f\" | "
            "grep -Ei \"^(anonymous_enable|write_enable|anon_upload_enable|anon_mkdir_write_enable)[[:space:]]*=\" || true; "
            "fi; done'"
        ),
    ),
    "samba": ServiceConfigCollectionPlan(
        service="samba",
        command=(
            "sh -lc 'for f in /etc/samba/smb.conf; do "
            "if [ -f \"$f\" ]; then "
            "printf \"source_file=%s\\n\" \"$f\"; "
            "grep -Eiv \"^[[:space:]]*(;|#|$)\" \"$f\" | "
            "grep -Ei \"(map to guest|guest ok|guest only|public|writable|writeable)[[:space:]]*=\" || true; "
            "fi; done'"
        ),
    ),
    "tomcat": ServiceConfigCollectionPlan(
        service="tomcat",
        command=(
            "sh -lc '"
            "for dir in /var/lib/tomcat*/webapps /usr/share/tomcat*/webapps /opt/tomcat/webapps; do "
            "[ -d \"$dir/manager\" ] && echo manager_exposed=true; "
            "([ -d \"$dir/examples\" ] || [ -d \"$dir/docs\" ]) && echo sample_apps_enabled=true; "
            "done; "
            "for f in /etc/tomcat*/tomcat-users.xml /var/lib/tomcat*/conf/tomcat-users.xml /opt/tomcat/conf/tomcat-users.xml; do "
            "if [ -f \"$f\" ] && grep -Eiq \"username=\\\"(tomcat|admin|manager|role1)\\\".*password=\\\"(tomcat|admin|manager|role1|s3cret)\\\"\" \"$f\"; then "
            "echo default_credentials=true; "
            "fi; "
            "done'"
        ),
    ),
    "apache": ServiceConfigCollectionPlan(
        service="apache",
        command=(
            "sh -lc '"
            "for d in /etc/apache2 /etc/httpd /usr/local/apache2/conf; do "
            "if [ -d \"$d\" ]; then "
            "grep -RH --exclude=\"*.bak.sa*\" --exclude=\"*.disabled.sa\" -Eiv \"^[[:space:]]*(#|$)\" \"$d\" 2>/dev/null | "
            "grep -Ei \"(Options[[:space:]].*Indexes|Dav[[:space:]]+On)\" || true; "
            "fi; "
            "done'"
        ),
    ),
    "nginx": ServiceConfigCollectionPlan(
        service="nginx",
        command=(
            "sh -lc '"
            "for d in /etc/nginx /usr/local/nginx/conf; do "
            "if [ -d \"$d\" ]; then "
            "grep -R --exclude=\"*.bak.sa*\" --exclude=\"*.disabled.sa\" -Eiv \"^[[:space:]]*(#|$)\" \"$d\" 2>/dev/null | "
            "grep -Ei \"(autoindex[[:space:]]+on|dav_methods[[:space:]])\" || true; "
            "fi; "
            "done'"
        ),
    ),
    "postgresql": ServiceConfigCollectionPlan(
        service="postgresql",
        command=(
            "sh -lc '"
            "for f in /etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf; do "
            "if [ -f \"$f\" ]; then "
            "grep -Eiv \"^[[:space:]]*(#|$)\" \"$f\" | grep -Ei \"[[:space:]]trust([[:space:]]|$)\" || true; "
            "fi; "
            "done; "
            "for f in /etc/postgresql/*/main/postgresql.conf /var/lib/pgsql/data/postgresql.conf /var/lib/postgresql/data/postgresql.conf; do "
            "if [ -f \"$f\" ]; then "
            "grep -Eiv \"^[[:space:]]*(#|$)\" \"$f\" | grep -Ei \"^listen_addresses[[:space:]]*=\" || true; "
            "fi; "
            "done'"
        ),
    ),
    "mysql": ServiceConfigCollectionPlan(
        service="mysql",
        command=(
            "sh -lc '"
            "for f in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/my.cnf /etc/my.cnf.d/*.cnf; do "
            "if [ -f \"$f\" ]; then "
            "printf \"source_file=%s\\n\" \"$f\"; "
            "grep -H -Eiv \"^[[:space:]]*(#|;|$)\" \"$f\" | "
            "grep -Ei \"^(skip[-_]grant[-_]tables|local[-_]infile|bind[-_]address|bind_address|mysqlx-bind-address|mysqlx_bind_address)([[:space:]]*(=|[[:space:]]|$))\" || true; "
            "fi; "
            "done'"
        ),
    ),
}

SERVICE_CONFIG_PACKAGE_PATTERNS: dict[str, tuple[str, ...]] = {
    "ssh": ("openssh", "sshd"),
    "redis": ("redis",),
    "vsftpd": ("vsftpd",),
    "samba": ("samba", "smb"),
    "tomcat": ("tomcat",),
    "apache": ("apache2", "httpd", "apache"),
    "nginx": ("nginx",),
    "postgresql": ("postgresql", "postgres"),
    "mysql": ("mysql", "mariadb"),
}


def detect_collectable_services(
    services: list[dict[str, str | int | None]],
    packages: list[dict[str, str | None]],
) -> list[str]:
    seen: set[str] = set()
    service_names = {str(item.get("name") or "").strip().lower() for item in services if isinstance(item, dict)}
    package_names = {str(item.get("name") or "").strip().lower() for item in packages if isinstance(item, dict)}

    for service, plan in SERVICE_CONFIG_COLLECTION_PLANS.items():
        if service in service_names:
            seen.add(service)
            continue
        if service == "ssh" and service_names.intersection({"sshd"}):
            seen.add(service)
            continue
        patterns = SERVICE_CONFIG_PACKAGE_PATTERNS.get(service, ())
        if any(_package_matches(name, patterns) for name in package_names):
            seen.add(service)
            continue
        if service == "vsftpd" and "ftp" in service_names:
            seen.add(service)
            continue
        if service == "samba" and service_names.intersection({"nmbd", "winbind"}):
            seen.add(service)
            continue
        if service == "postgresql" and service_names.intersection({"postgres"}):
            seen.add(service)
            continue
        if service == "mysql" and service_names.intersection({"mysqld", "mariadbd"}):
            seen.add(service)
            continue
        if service == "apache" and service_names.intersection({"apache2", "httpd"}):
            seen.add(service)
            continue
        if service == "tomcat" and any(name.startswith("tomcat") for name in service_names):
            seen.add(service)
            continue

    return [item for item in SERVICE_CONFIG_COLLECTION_PLANS if item in seen]


def parse_service_config(service: str, raw: str | None) -> dict[str, Any]:
    normalized = service.strip().lower()
    cleaned_raw = _strip_runtime_backup_lines(raw)
    if normalized == "ssh":
        return _parse_ssh_config(cleaned_raw)
    if normalized == "redis":
        return _parse_redis_config(cleaned_raw)
    if normalized == "vsftpd":
        return _parse_vsftpd_config(cleaned_raw)
    if normalized == "samba":
        return _parse_samba_config(cleaned_raw)
    if normalized == "tomcat":
        return _parse_bool_flags(cleaned_raw, {"manager_exposed", "sample_apps_enabled", "default_credentials"})
    if normalized == "apache":
        return _parse_httpd_config(cleaned_raw, webdav_token=r"\bDav\s+On\b")
    if normalized == "nginx":
        return _parse_nginx_config(cleaned_raw)
    if normalized == "postgresql":
        return _parse_postgresql_config(cleaned_raw)
    if normalized == "mysql":
        return _parse_mysql_config(cleaned_raw)
    return {}


def _package_matches(name: str, patterns: tuple[str, ...]) -> bool:
    return any(pattern in name for pattern in patterns)


def _parse_ssh_config(raw: str | None) -> dict[str, Any]:
    values = _parse_key_value_lines(raw, separator=" ")
    result: dict[str, Any] = {}
    source_files = _extract_source_files(raw)
    if source_files:
        result["source_files"] = source_files
    if "passwordauthentication" in values:
        result["password_authentication"] = _parse_bool(values["passwordauthentication"])
    if "permitrootlogin" in values:
        permit_value = values["permitrootlogin"].strip().lower()
        result["permit_root_login"] = permit_value not in {"no", "false", "off"}
    if "pubkeyauthentication" in values:
        result["pubkey_authentication"] = _parse_bool(values["pubkeyauthentication"])
    if "permitemptypasswords" in values:
        result["permit_empty_passwords"] = _parse_bool(values["permitemptypasswords"])
    return {key: value for key, value in result.items() if value is not None}


def _parse_redis_config(raw: str | None) -> dict[str, Any]:
    values = _parse_key_value_lines(raw, separator=" ")
    result: dict[str, Any] = {}
    if "protected-mode" in values:
        result["protected_mode"] = _parse_bool(values["protected-mode"])
    if "requirepass" in values:
        result["requirepass"] = values["requirepass"].strip().strip("\"'")
    if "bind" in values:
        bind_value = values["bind"].strip().lower()
        tokens = bind_value.split()
        result["bind_all_interfaces"] = any(token in {"0.0.0.0", "::", "*"} for token in tokens)
    return {key: value for key, value in result.items() if value is not None}


def _parse_vsftpd_config(raw: str | None) -> dict[str, Any]:
    values = _parse_key_value_lines(raw, separator="=")
    anonymous_enabled = _parse_bool(values.get("anonymous_enable"))
    write_enabled = _parse_bool(values.get("write_enable"))
    anon_upload_enabled = _parse_bool(values.get("anon_upload_enable"))
    anon_mkdir_enabled = _parse_bool(values.get("anon_mkdir_write_enable"))
    result: dict[str, Any] = {}
    if anonymous_enabled is not None:
        result["anonymous_enabled"] = anonymous_enabled
    anon_write_flags = [flag for flag in [write_enabled, anon_upload_enabled, anon_mkdir_enabled] if flag is not None]
    if anonymous_enabled is not None or anon_write_flags:
        result["anonymous_write_enabled"] = bool(anonymous_enabled and any(anon_write_flags))
    return result


def _parse_samba_config(raw: str | None) -> dict[str, Any]:
    guest_enabled = False
    writable_enabled = False
    source_files = _extract_source_files(raw)
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";") or "=" not in line:
            continue
        key, value = [item.strip().lower() for item in line.split("=", 1)]
        bool_value = _parse_bool(value)
        if key in {"guest ok", "guest only", "public"} and bool_value is True:
            guest_enabled = True
        if key == "map to guest" and value not in {"never", "no"}:
            guest_enabled = True
        if key in {"writable", "writeable"} and bool_value is True:
            writable_enabled = True
    result: dict[str, Any] = {}
    if guest_enabled:
        result["guest_access"] = True
    if guest_enabled and writable_enabled:
        result["writable_guest_share"] = True
    if source_files:
        result["source_files"] = source_files
    return result


def _parse_httpd_config(raw: str | None, *, webdav_token: str) -> dict[str, Any]:
    content = raw or ""
    result: dict[str, Any] = {}
    source_files = _extract_source_files(raw)
    if re.search(r"\bOptions\b[^\n#]*\bIndexes\b", content, flags=re.IGNORECASE):
        result["directory_listing_enabled"] = True
    if re.search(webdav_token, content, flags=re.IGNORECASE):
        result["webdav_enabled"] = True
    if source_files:
        result["source_files"] = source_files
    return result


def _parse_nginx_config(raw: str | None) -> dict[str, Any]:
    content = raw or ""
    result: dict[str, Any] = {}
    source_files = _extract_source_files(raw)
    if re.search(r"\bautoindex\s+on\b", content, flags=re.IGNORECASE):
        result["directory_listing_enabled"] = True
    if re.search(r"\bdav_methods\b", content, flags=re.IGNORECASE):
        result["webdav_enabled"] = True
    if source_files:
        result["source_files"] = source_files
    return result


def _parse_postgresql_config(raw: str | None) -> dict[str, Any]:
    content = raw or ""
    result: dict[str, Any] = {}
    if re.search(r"(^|\s)trust(\s|$)", content, flags=re.IGNORECASE | re.MULTILINE):
        result["trust_auth_enabled"] = True

    for line in content.splitlines():
        normalized = line.strip()
        if not normalized.lower().startswith("listen_addresses"):
            continue
        _, value = normalized.split("=", 1)
        value = value.strip().strip("\"'")
        tokens = [token.strip().strip("\"'") for token in value.split(",")]
        if any(token in {"*", "0.0.0.0", "::"} for token in tokens):
            result["listen_all_interfaces"] = True
            break
    return result


def _parse_mysql_config(raw: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    source_files = _extract_source_files(raw)
    if source_files:
        result["source_files"] = source_files
    for line in (raw or "").splitlines():
        normalized = line.strip()
        if not normalized or normalized.startswith("#") or normalized.startswith(";"):
            continue
        if normalized.startswith("source_file="):
            continue
        if ":" in normalized and normalized.split(":", 1)[0].startswith("/"):
            _, normalized = normalized.split(":", 1)
            normalized = normalized.strip()
            if not normalized:
                continue

        if "=" in normalized:
            key, value = normalized.split("=", 1)
            parsed_value = value.strip()
        else:
            parts = normalized.split(None, 1)
            key = parts[0]
            parsed_value = parts[1].strip() if len(parts) > 1 else None

        lowered_key = key.strip().lower()
        if lowered_key in {"skip-grant-tables", "skip_grant_tables"}:
            parsed = _parse_bool(parsed_value) if parsed_value is not None else True
            result["skip_grant_tables"] = True if parsed is None else parsed
            continue
        if lowered_key in {"local-infile", "local_infile"}:
            parsed = _parse_bool(parsed_value) if parsed_value is not None else True
            result["local_infile"] = True if parsed is None else parsed
            continue
        if lowered_key in {"bind-address", "bind_address", "mysqlx-bind-address", "mysqlx_bind_address"}:
            tokens = [
                token.strip().strip("\"'")
                for token in str(parsed_value or "").split(",")
                if token.strip().strip("\"'")
            ]
            if any(token in {"*", "0.0.0.0", "::"} for token in tokens):
                result["bind_all_interfaces"] = True
            elif tokens:
                result["bind_all_interfaces"] = False
    return {key: value for key, value in result.items() if value is not None}


def _parse_bool_flags(raw: str | None, keys: set[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in (raw or "").splitlines():
        if "=" not in line:
            continue
        key, value = [item.strip().lower() for item in line.split("=", 1)]
        if key in keys:
            parsed = _parse_bool(value)
            if parsed is not None:
                result[key] = parsed
    return result


def _parse_key_value_lines(raw: str | None, *, separator: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (raw or "").splitlines():
        normalized = line.strip()
        if not normalized or normalized.startswith("#") or normalized.startswith(";"):
            continue
        if normalized.startswith("source_file="):
            continue
        if ":" in normalized and normalized.split(":", 1)[0].startswith("/"):
            _, normalized = normalized.split(":", 1)
            normalized = normalized.strip()
            if not normalized:
                continue
        if separator == " ":
            parts = normalized.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts
        else:
            if separator not in normalized:
                continue
            key, value = normalized.split(separator, 1)
        values[key.strip().lower()] = value.strip()
    return values


def _parse_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    normalized = raw.strip().strip("\"'").lower()
    if normalized in {"yes", "true", "on", "1"}:
        return True
    if normalized in {"no", "false", "off", "0"}:
        return False
    return None


def _is_runtime_backup_path(path: str) -> bool:
    normalized = str(path or "").strip().lower()
    if not normalized:
        return False
    return ".bak.sa." in normalized or normalized.endswith(".bak.sa") or normalized.endswith(".disabled.sa")


def _strip_runtime_backup_lines(raw: str | None) -> str:
    kept: list[str] = []
    for line in (raw or "").splitlines():
        normalized = line.strip()
        if normalized.startswith("source_file="):
            path = normalized.split("=", 1)[1].strip()
            if _is_runtime_backup_path(path):
                continue
        elif ":" in normalized:
            prefix = normalized.split(":", 1)[0].strip()
            if prefix.startswith("/") and _is_runtime_backup_path(prefix):
                continue
        kept.append(line)
    return "\n".join(kept)


def _extract_source_files(raw: str | None) -> list[str]:
    seen: list[str] = []
    for line in (raw or "").splitlines():
        normalized = line.strip()
        if normalized.startswith("source_file="):
            path = normalized.split("=", 1)[1].strip()
            if path and not _is_runtime_backup_path(path) and path not in seen:
                seen.append(path)
            continue
        if ":" in normalized:
            prefix = normalized.split(":", 1)[0].strip()
            if prefix.startswith("/") and not _is_runtime_backup_path(prefix) and prefix not in seen:
                seen.append(prefix)
    return seen[:20]
