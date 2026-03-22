from __future__ import annotations

import asyncio
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

from app.scanner.service_fingerprint import infer_service_aliases

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class NmapScriptDefinition:
    script_id: str
    services: frozenset[str]
    tls_required: bool | None = None
    vuln: bool = False
    ports: frozenset[int] = frozenset()
    host_script: bool = False


@dataclass(frozen=True, slots=True)
class NmapScriptBatchResult:
    by_host: dict[str, dict[int, dict[str, Any]]]
    error_count: int = 0
    timeout_count: int = 0


WHITELIST_NSE_SCRIPTS: tuple[NmapScriptDefinition, ...] = (
    NmapScriptDefinition("ftp-anon", frozenset({"ftp", "vsftpd"}), ports=frozenset({21})),
    NmapScriptDefinition("ftp-syst", frozenset({"ftp", "vsftpd"}), ports=frozenset({21})),
    NmapScriptDefinition("http-title", frozenset({"http", "https", "apache", "nginx", "tomcat", "php", "phpmyadmin", "twiki"})),
    NmapScriptDefinition("http-headers", frozenset({"http", "https", "apache", "nginx", "tomcat", "php", "phpmyadmin", "twiki"})),
    NmapScriptDefinition("http-methods", frozenset({"http", "https", "apache", "nginx", "tomcat", "php", "phpmyadmin", "twiki"})),
    NmapScriptDefinition("http-enum", frozenset({"http", "https", "apache", "nginx", "tomcat", "php", "phpmyadmin", "twiki"}), host_script=False),
    NmapScriptDefinition("http-git", frozenset({"http", "https", "apache", "nginx", "php"})),
    NmapScriptDefinition("http-config-backup", frozenset({"http", "https", "apache", "nginx", "php"})),
    NmapScriptDefinition("redis-info", frozenset({"redis"})),
    NmapScriptDefinition("smtp-commands", frozenset({"smtp"})),
    NmapScriptDefinition("ssh2-enum-algos", frozenset({"ssh"})),
    NmapScriptDefinition("ssh-auth-methods", frozenset({"ssh"})),
    NmapScriptDefinition("ssl-cert", frozenset({"https", "http", "smtp", "imap", "pop3"}), tls_required=True),
    NmapScriptDefinition("smb-enum-shares", frozenset({"samba"}), ports=frozenset({139, 445}), host_script=True),
    NmapScriptDefinition("smb-enum-users", frozenset({"samba"}), ports=frozenset({139, 445}), host_script=True),
    NmapScriptDefinition("smb-vuln-ms17-010", frozenset({"samba"}), vuln=True, ports=frozenset({139, 445}), host_script=True),
    NmapScriptDefinition("ftp-vsftpd-backdoor", frozenset({"ftp", "vsftpd"}), vuln=True, ports=frozenset({21})),
    NmapScriptDefinition("http-shellshock", frozenset({"http", "https", "apache", "nginx"}), vuln=True),
    NmapScriptDefinition("http-vuln-cve2012-1823", frozenset({"http", "https", "apache", "nginx", "tomcat"}), vuln=True),
    NmapScriptDefinition("http-vuln-cve2014-3704", frozenset({"http", "https", "apache", "nginx", "php"}), vuln=True),
    NmapScriptDefinition("http-vuln-cve2017-5638", frozenset({"http", "https", "apache", "nginx", "tomcat"}), vuln=True),
    NmapScriptDefinition("ssl-heartbleed", frozenset({"https", "http", "smtp", "imap", "pop3"}), tls_required=True, vuln=True),
)


def _to_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _normalize_service(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower()
    return normalized or "unknown"


def _allow_script_for_scan_profile(
    script_id: str,
    *,
    aliases: set[str],
    tls_detected: bool,
    scan_profile: str,
) -> bool:
    if scan_profile != "collection":
        return True
    if script_id == "http-vuln-cve2012-1823":
        return bool(aliases.intersection({"http", "https", "apache", "nginx", "php"})) and "tomcat" not in aliases
    if script_id == "http-shellshock":
        return bool(aliases.intersection({"http", "https", "apache", "nginx"})) and "tomcat" not in aliases
    if script_id == "http-vuln-cve2014-3704":
        return bool(aliases.intersection({"http", "https", "apache", "nginx", "php"}))
    if script_id == "http-vuln-cve2017-5638":
        return bool(aliases.intersection({"http", "https", "apache", "nginx", "tomcat"}))
    if script_id == "ssl-heartbleed":
        return tls_detected and bool(aliases.intersection({"https", "apache", "nginx", "smtp", "imap", "pop3"}))
    if script_id == "ftp-vsftpd-backdoor":
        return bool(aliases.intersection({"ftp", "vsftpd"}))
    return True


def select_nse_scripts_for_record(
    record: dict[str, Any],
    *,
    include_vuln: bool = True,
    scan_profile: str = "discovery",
) -> list[str]:
    aliases = set(infer_service_aliases(record))
    port = _to_port(record.get("port"))
    tls_detected = bool(record.get("tls_detected") is True)
    if not aliases:
        return []

    scripts: list[str] = []
    for definition in WHITELIST_NSE_SCRIPTS:
        if definition.vuln and not include_vuln:
            continue
        if definition.ports and port not in definition.ports:
            continue
        if definition.tls_required is True and not tls_detected:
            continue
        if definition.tls_required is False and tls_detected:
            continue
        if aliases and not aliases.intersection(definition.services):
            continue
        if not _allow_script_for_scan_profile(
            definition.script_id,
            aliases=aliases,
            tls_detected=tls_detected,
            scan_profile=scan_profile,
        ):
            continue
        scripts.append(definition.script_id)
    return scripts


def build_nse_summary(requested_scripts: list[str], results: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized_results = results if isinstance(results, dict) else {}
    requested = list(dict.fromkeys([item for item in requested_scripts if isinstance(item, str) and item.strip()]))
    hit_scripts = [
        script_id
        for script_id in requested
        if isinstance(normalized_results.get(script_id), dict) and normalized_results[script_id].get("hit") is True
    ]
    summaries = {
        script_id: str((normalized_results.get(script_id) or {}).get("summary") or "")
        for script_id in requested
        if isinstance(normalized_results.get(script_id), dict)
    }
    return {
        "requested_scripts": requested,
        "returned_scripts": [script_id for script_id in requested if script_id in normalized_results],
        "hit_scripts": hit_scripts,
        "script_count": len(requested),
        "hit_count": len(hit_scripts),
        "script_summaries": summaries,
    }


def compact_nse_results(results: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(results, dict):
        return {}
    compact: dict[str, Any] = {}
    for script_id, payload in results.items():
        if not isinstance(script_id, str) or not isinstance(payload, dict):
            continue
        compact[script_id] = {
            key: value
            for key, value in payload.items()
            if key not in {"raw_output", "structured"}
        }
    return compact


def filter_nse_results(results: dict[str, Any] | None, script_ids: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(results, dict):
        return {}
    if not script_ids:
        return compact_nse_results(results)
    return compact_nse_results({key: value for key, value in results.items() if key in script_ids})


@dataclass(slots=True)
class AsyncNmapScriptEnricher:
    mode: str = "whitelist"
    timeout_seconds: int = 8
    host_concurrency: int = 8

    async def enrich_hosts(self, targets: list[dict[str, Any]]) -> NmapScriptBatchResult:
        if self.mode != "whitelist":
            return NmapScriptBatchResult(by_host={}, error_count=0)
        if not self._has_nmap():
            logger.info("nmap not available, skip NSE enrichment")
            return NmapScriptBatchResult(by_host={}, error_count=0)

        semaphore = asyncio.Semaphore(max(1, self.host_concurrency))
        tasks = [
            asyncio.create_task(self._run_one_target(semaphore, target))
            for target in targets
            if isinstance(target, dict) and target.get("ip") and target.get("ports") and target.get("scripts")
        ]
        if not tasks:
            return NmapScriptBatchResult(by_host={}, error_count=0)

        results = await asyncio.gather(*tasks)
        by_host = {ip: by_port for ip, by_port, _ in results if ip and by_port}
        error_count = sum(1 for _, _, status in results if status in {"timeout", "error"})
        timeout_count = sum(1 for _, _, status in results if status == "timeout")
        return NmapScriptBatchResult(by_host=by_host, error_count=error_count, timeout_count=timeout_count)

    def _has_nmap(self) -> bool:
        return shutil.which("nmap") is not None

    async def _run_one_target(
        self,
        semaphore: asyncio.Semaphore,
        target: dict[str, Any],
    ) -> tuple[str, dict[int, dict[str, Any]], str]:
        ip = str(target.get("ip") or "").strip()
        ports = sorted({_to_port(item) for item in target.get("ports", []) if _to_port(item) is not None})
        scripts = sorted({str(item).strip() for item in target.get("scripts", []) if str(item).strip()})
        if not ip or not ports or not scripts:
            return ip, {}, "skipped"

        async with semaphore:
            cmd = [
                "nmap",
                "-Pn",
                "-n",
                "-p",
                ",".join(str(port) for port in ports),
                "--script",
                ",".join(scripts),
                "--script-timeout",
                f"{max(1, int(self.timeout_seconds))}s",
                ip,
                "-oX",
                "-",
            ]
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=float(self.timeout_seconds) + 3.0)
            except asyncio.TimeoutError:
                logger.info("nmap NSE enrichment timeout for host=%s", ip)
                return ip, {}, "timeout"
            except FileNotFoundError:
                return ip, {}, "error"
            except Exception as exc:  # pragma: no cover - runtime dependent
                logger.info("nmap NSE enrichment failed for host=%s: %s", ip, exc)
                return ip, {}, "error"

            if process.returncode not in {0, 1}:
                logger.info(
                    "nmap NSE enrichment non-zero exit for host=%s: rc=%s stderr=%s",
                    ip,
                    process.returncode,
                    stderr.decode("utf-8", errors="ignore"),
                )
                return ip, {}, "error"
            return (
                ip,
                self.parse_xml_output(
                    ip,
                    stdout.decode("utf-8", errors="ignore"),
                    allowed_scripts=set(scripts),
                    requested_by_port=target.get("port_scripts") if isinstance(target.get("port_scripts"), dict) else None,
                ),
                "ok",
            )

    @classmethod
    def parse_xml_output(
        cls,
        ip: str,
        output: str,
        *,
        allowed_scripts: set[str] | None = None,
        requested_by_port: dict[int, list[str]] | dict[str, list[str]] | None = None,
    ) -> dict[int, dict[str, Any]]:
        by_port: dict[int, dict[str, Any]] = {}
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return by_port

        for host in root.findall("host"):
            address_node = host.find("address")
            if address_node is None or address_node.get("addr") != ip:
                continue
            ports_node = host.find("ports")
            if ports_node is None:
                continue
            for port_node in ports_node.findall("port"):
                port = _to_port(port_node.get("portid"))
                if port is None:
                    continue
                state_node = port_node.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue
                parsed_scripts: dict[str, Any] = {}
                for script_node in port_node.findall("script"):
                    script_id = str(script_node.get("id") or "").strip()
                    if not script_id:
                        continue
                    if allowed_scripts and script_id not in allowed_scripts:
                        continue
                    output_text = str(script_node.get("output") or "").strip()
                    structured = cls._parse_script_children(script_node)
                    parsed_scripts[script_id] = cls._normalize_script_result(
                        script_id=script_id,
                        output_text=output_text,
                        structured=structured,
                    )
                if parsed_scripts:
                    existing = by_port.get(port, {})
                    existing.update(parsed_scripts)
                    by_port[port] = existing

            hostscript_node = host.find("hostscript")
            if hostscript_node is None:
                continue
            for script_node in hostscript_node.findall("script"):
                script_id = str(script_node.get("id") or "").strip()
                if not script_id:
                    continue
                if allowed_scripts and script_id not in allowed_scripts:
                    continue
                target_port = cls._resolve_hostscript_port(script_id, requested_by_port)
                if target_port is None:
                    continue
                output_text = str(script_node.get("output") or "").strip()
                structured = cls._parse_script_children(script_node)
                existing = by_port.get(target_port, {})
                existing[script_id] = cls._normalize_script_result(
                    script_id=script_id,
                    output_text=output_text,
                    structured=structured,
                )
                by_port[target_port] = existing
        return by_port

    @classmethod
    def _resolve_hostscript_port(
        cls,
        script_id: str,
        requested_by_port: dict[int, list[str]] | dict[str, list[str]] | None,
    ) -> int | None:
        if not isinstance(requested_by_port, dict):
            return None
        candidates: list[int] = []
        for raw_port, scripts in requested_by_port.items():
            port = _to_port(raw_port)
            if port is None or not isinstance(scripts, list):
                continue
            if script_id in {str(item).strip() for item in scripts if isinstance(item, str)}:
                candidates.append(port)
        if not candidates:
            return None
        for preferred in (445, 139):
            if preferred in candidates:
                return preferred
        return min(candidates)

    @classmethod
    def _parse_script_children(cls, script_node: ET.Element) -> Any:
        values: dict[str, Any] = {}
        items: list[Any] = []
        for child in script_node:
            if child.tag == "elem":
                parsed_value: Any = (child.text or "").strip()
            elif child.tag == "table":
                parsed_value = cls._parse_table(child)
            else:
                continue
            key = child.get("key")
            if key:
                if key in values:
                    existing = values[key]
                    if not isinstance(existing, list):
                        values[key] = [existing]
                    values[key].append(parsed_value)
                else:
                    values[key] = parsed_value
            else:
                items.append(parsed_value)
        if values and items:
            values["_items"] = items
        if values:
            return values
        if items:
            return items
        return {}

    @classmethod
    def _parse_table(cls, table_node: ET.Element) -> Any:
        values: dict[str, Any] = {}
        items: list[Any] = []
        for child in table_node:
            if child.tag == "elem":
                parsed_value: Any = (child.text or "").strip()
            elif child.tag == "table":
                parsed_value = cls._parse_table(child)
            else:
                continue
            key = child.get("key")
            if key:
                if key in values:
                    existing = values[key]
                    if not isinstance(existing, list):
                        values[key] = [existing]
                    values[key].append(parsed_value)
                else:
                    values[key] = parsed_value
            else:
                items.append(parsed_value)
        if values and items:
            values["_items"] = items
        if values:
            return values
        return items

    @classmethod
    def _normalize_script_result(
        cls,
        *,
        script_id: str,
        output_text: str,
        structured: Any,
    ) -> dict[str, Any]:
        base = {
            "hit": bool(output_text.strip()),
            "summary": cls._summarize_output(output_text),
            "raw_output": output_text,
            "structured": structured if structured not in ({}, []) else {},
        }
        if script_id == "ftp-anon":
            return cls._normalize_ftp_anon(base, output_text)
        if script_id == "ftp-syst":
            return cls._normalize_ftp_syst(base, output_text)
        if script_id == "http-title":
            return cls._normalize_http_title(base, output_text)
        if script_id == "http-headers":
            return cls._normalize_http_headers(base, output_text)
        if script_id == "http-methods":
            return cls._normalize_http_methods(base, output_text)
        if script_id == "http-enum":
            return cls._normalize_http_enum(base, output_text)
        if script_id == "http-git":
            return cls._normalize_http_git(base, output_text)
        if script_id == "http-config-backup":
            return cls._normalize_http_config_backup(base, output_text)
        if script_id == "redis-info":
            return cls._normalize_redis_info(base, output_text)
        if script_id == "smtp-commands":
            return cls._normalize_smtp_commands(base, output_text)
        if script_id == "ssh2-enum-algos":
            return cls._normalize_ssh_algorithms(base, structured)
        if script_id == "ssh-auth-methods":
            return cls._normalize_ssh_auth_methods(base, structured)
        if script_id == "ssl-cert":
            return cls._normalize_ssl_cert(base, output_text)
        if script_id == "smb-enum-shares":
            return cls._normalize_smb_enum_shares(base, structured)
        if script_id == "smb-enum-users":
            return cls._normalize_smb_enum_users(base, output_text)
        if script_id in {
            "ftp-vsftpd-backdoor",
            "http-shellshock",
            "http-vuln-cve2012-1823",
            "http-vuln-cve2014-3704",
            "http-vuln-cve2017-5638",
            "smb-vuln-ms17-010",
            "ssl-heartbleed",
        }:
            return cls._normalize_vuln_probe(base, output_text)
        return base

    @staticmethod
    def _summarize_output(output_text: str) -> str:
        cleaned = " ".join(output_text.split())
        if len(cleaned) <= 160:
            return cleaned
        return f"{cleaned[:157]}..."

    @staticmethod
    def _normalize_ftp_anon(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        lines = [line.strip() for line in output_text.splitlines() if line.strip()]
        writable_entries = [line for line in lines if "write" in line.lower()]
        base.update(
            {
                "hit": "anonymous ftp login allowed" in output_text.lower(),
                "anonymous_allowed": "anonymous ftp login allowed" in output_text.lower(),
                "writable_entries": writable_entries,
                "listing": lines[1:] if len(lines) > 1 else [],
            }
        )
        return base

    @staticmethod
    def _normalize_ftp_syst(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        lines = [line.strip() for line in output_text.splitlines() if line.strip()]
        base.update(
            {
                "system_type": lines[0] if lines else "",
                "status_lines": lines[1:] if len(lines) > 1 else [],
            }
        )
        return base

    @staticmethod
    def _normalize_http_title(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        title = output_text.strip()
        base.update({"title": title})
        return base

    @staticmethod
    def _normalize_http_headers(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        headers: dict[str, str] = {}
        for line in output_text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        base.update({"headers": headers})
        return base

    @staticmethod
    def _normalize_http_methods(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        supported_match = re.search(r"supported methods:\s*(.+)", output_text, flags=re.IGNORECASE)
        risky_match = re.search(r"potentially risky methods:\s*(.+)", output_text, flags=re.IGNORECASE)
        supported_methods = (
            [item.strip().upper() for item in re.split(r"[\s,]+", supported_match.group(1).strip()) if item.strip()]
            if supported_match
            else []
        )
        risky_methods = (
            [item.strip().upper() for item in re.split(r"[\s,]+", risky_match.group(1).strip()) if item.strip()]
            if risky_match
            else []
        )
        base.update(
            {
                "supported_methods": supported_methods,
                "risky_methods": risky_methods,
                "hit": bool(risky_methods),
            }
        )
        if risky_methods:
            base["summary"] = f"检测到风险方法：{', '.join(risky_methods)}"
        return base

    @staticmethod
    def _normalize_http_enum(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        discovered_paths = []
        for line in output_text.splitlines():
            match = re.match(r"\s*(/[^:\s]+)\s*:", line.strip())
            if match:
                discovered_paths.append(match.group(1).strip())
        unique_paths = sorted(dict.fromkeys(discovered_paths))
        base.update(
            {
                "hit": bool(unique_paths),
                "discovered_paths": unique_paths,
                "path_count": len(unique_paths),
            }
        )
        if unique_paths:
            base["summary"] = f"发现 {len(unique_paths)} 个典型路径"
        return base

    @staticmethod
    def _normalize_http_git(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        exposed_paths = sorted(
            dict.fromkeys(
                match.group(1).strip()
                for line in output_text.splitlines()
                for match in [re.match(r"\s*(/[^:\s]*\.git(?:/HEAD)?)\s*:?", line.strip(), flags=re.IGNORECASE)]
                if match
            )
        )
        git_head_exposed = ".git/head" in output_text.lower() or any(path.lower().endswith(".git/head") for path in exposed_paths)
        base.update(
            {
                "hit": bool(exposed_paths or git_head_exposed),
                "git_head_exposed": git_head_exposed,
                "exposed_paths": exposed_paths,
            }
        )
        if git_head_exposed:
            base["summary"] = "发现可直接访问的 .git/HEAD"
        elif exposed_paths:
            base["summary"] = f"发现 {len(exposed_paths)} 个 .git 暴露路径"
        return base

    @staticmethod
    def _normalize_http_config_backup(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        exposed_files = sorted(
            dict.fromkeys(
                match.group(1).strip()
                for line in output_text.splitlines()
                for match in [re.match(r"\s*(/[^:\s]+)\s*:?", line.strip())]
                if match
            )
        )
        base.update(
            {
                "hit": bool(exposed_files),
                "exposed_files": exposed_files,
            }
        )
        if exposed_files:
            base["summary"] = f"发现 {len(exposed_files)} 个配置备份文件"
        return base

    @staticmethod
    def _normalize_redis_info(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        info: dict[str, str] = {}
        for line in output_text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key:
                info[key] = value
        base.update(
            {
                "info": info,
                "redis_version": info.get("redis_version"),
            }
        )
        return base

    @staticmethod
    def _normalize_smtp_commands(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        match = re.search(r"supported commands:\s*(.+)", output_text, flags=re.IGNORECASE)
        commands = (
            [item.strip().upper() for item in re.split(r"[\s,]+", match.group(1).strip()) if item.strip()]
            if match
            else []
        )
        base.update({"supported_commands": commands})
        return base

    @staticmethod
    def _normalize_ssh_algorithms(base: dict[str, Any], structured: Any) -> dict[str, Any]:
        groups = list(structured.keys()) if isinstance(structured, dict) else []
        base.update({"algorithm_groups": groups})
        return base

    @staticmethod
    def _normalize_ssh_auth_methods(base: dict[str, Any], structured: Any) -> dict[str, Any]:
        auth_methods = []
        banner = ""
        if isinstance(structured, dict):
            methods = structured.get("Supported authentication methods")
            if isinstance(methods, list):
                auth_methods = [str(item).strip().lower() for item in methods if str(item).strip()]
            elif isinstance(methods, str) and methods.strip():
                auth_methods = [methods.strip().lower()]
            banner = str(structured.get("Banner") or "").strip()
        base.update(
            {
                "hit": bool(auth_methods),
                "auth_methods": auth_methods,
                "banner": banner,
            }
        )
        return base

    @staticmethod
    def _normalize_ssl_cert(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        subject_match = re.search(r"Subject:\s*(.+)", output_text, flags=re.IGNORECASE)
        issuer_match = re.search(r"Issuer:\s*(.+)", output_text, flags=re.IGNORECASE)
        not_before = re.search(r"Not valid before:\s*(.+)", output_text, flags=re.IGNORECASE)
        not_after = re.search(r"Not valid after:\s*(.+)", output_text, flags=re.IGNORECASE)
        base.update(
            {
                "subject": subject_match.group(1).strip() if subject_match else "",
                "issuer": issuer_match.group(1).strip() if issuer_match else "",
                "not_valid_before": not_before.group(1).strip() if not_before else "",
                "not_valid_after": not_after.group(1).strip() if not_after else "",
            }
        )
        return base

    @staticmethod
    def _normalize_smb_enum_shares(base: dict[str, Any], structured: Any) -> dict[str, Any]:
        share_names: list[str] = []
        anonymous_shares: list[str] = []
        writable_shares: list[str] = []
        account_used = ""
        if isinstance(structured, dict):
            account_used = str(structured.get("account_used") or "").strip()
            for key, value in structured.items():
                if key in {"account_used", "note"} or not isinstance(value, dict):
                    continue
                share_name = str(key).strip()
                if not share_name:
                    continue
                share_names.append(share_name)
                anonymous_access = str(value.get("Anonymous access") or "").strip().upper()
                current_access = str(value.get("Current user access") or "").strip().upper()
                if anonymous_access and anonymous_access != "<NONE>":
                    anonymous_shares.append(share_name)
                if "WRITE" in anonymous_access or "WRITE" in current_access:
                    writable_shares.append(share_name)
        share_names = sorted(dict.fromkeys(share_names))
        anonymous_shares = sorted(dict.fromkeys(anonymous_shares))
        writable_shares = sorted(dict.fromkeys(writable_shares))
        base.update({"hit": bool(share_names), "share_names": share_names, "account_used": account_used})
        if anonymous_shares:
            base["anonymous_shares"] = anonymous_shares
        else:
            base.pop("anonymous_shares", None)
        if writable_shares:
            base["writable_shares"] = writable_shares
        else:
            base.pop("writable_shares", None)
        if share_names:
            base["summary"] = f"枚举到 {len(share_names)} 个共享"
        return base

    @staticmethod
    def _normalize_smb_enum_users(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        usernames: list[str] = []
        for line in output_text.splitlines():
            summary_match = re.search(r"Users:\s*(.+)", line, flags=re.IGNORECASE)
            if summary_match:
                usernames.extend(
                    item.strip()
                    for item in summary_match.group(1).split(",")
                    if item.strip()
                )
                continue
            detail_match = re.search(r"\\([^\s\\]+)\s+\(RID:", line)
            if detail_match:
                usernames.append(detail_match.group(1).strip())
        unique_users = sorted(dict.fromkeys(usernames))
        base.update({"hit": bool(unique_users)})
        if unique_users:
            base["usernames"] = unique_users
            base["user_count"] = len(unique_users)
        else:
            base.pop("usernames", None)
            base.pop("user_count", None)
        if unique_users:
            base["summary"] = f"枚举到 {len(unique_users)} 个账户"
        return base

    @staticmethod
    def _normalize_vuln_probe(base: dict[str, Any], output_text: str) -> dict[str, Any]:
        vulnerable = "vulnerable" in output_text.lower()
        state_match = re.search(r"State:\s*([A-Z]+)", output_text)
        base.update(
            {
                "hit": vulnerable,
                "vulnerable": vulnerable,
                "state": state_match.group(1) if state_match else "",
            }
        )
        if vulnerable and base.get("summary"):
            base["summary"] = f"命中漏洞特征：{base['summary']}"
        return base
