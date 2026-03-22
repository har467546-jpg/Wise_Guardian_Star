from __future__ import annotations

from app.scanner.nmap_nse import AsyncNmapScriptEnricher, build_nse_summary, filter_nse_results, select_nse_scripts_for_record


def test_select_nse_scripts_for_tls_http_service() -> None:
    scripts = select_nse_scripts_for_record(
        {
            "port": 8443,
            "service": "https",
            "application_service": "tomcat",
            "tls_detected": True,
            "banner": "Apache Tomcat/9.0.82",
        },
        include_vuln=True,
    )

    assert "http-title" in scripts
    assert "http-headers" in scripts
    assert "http-methods" in scripts
    assert "http-enum" in scripts
    assert "ssl-cert" in scripts
    assert "http-vuln-cve2017-5638" in scripts
    assert "ssl-heartbleed" in scripts


def test_select_nse_scripts_for_collection_profile_is_stricter_for_php_cgi_probe() -> None:
    scripts = select_nse_scripts_for_record(
        {
            "port": 8443,
            "service": "https",
            "application_service": "tomcat",
            "tls_detected": True,
            "banner": "Apache Tomcat/9.0.82",
        },
        include_vuln=True,
        scan_profile="collection",
    )

    assert "http-title" in scripts
    assert "http-enum" in scripts
    assert "ssl-cert" in scripts
    assert "http-vuln-cve2017-5638" in scripts
    assert "ssl-heartbleed" in scripts
    assert "http-vuln-cve2012-1823" not in scripts


def test_select_nse_scripts_for_samba_and_ssh_services() -> None:
    samba_scripts = select_nse_scripts_for_record(
        {
            "port": 445,
            "service": "samba",
            "application_service": "samba",
            "banner": "Samba smbd 3.0.20",
        },
        include_vuln=True,
    )
    ssh_scripts = select_nse_scripts_for_record(
        {
            "port": 22,
            "service": "ssh",
            "banner": "SSH-2.0-OpenSSH_7.4",
        },
        include_vuln=True,
    )

    assert "smb-enum-shares" in samba_scripts
    assert "smb-enum-users" in samba_scripts
    assert "smb-vuln-ms17-010" in samba_scripts
    assert "ssh-auth-methods" in ssh_scripts


def test_select_nse_scripts_includes_new_high_value_web_scripts() -> None:
    scripts = select_nse_scripts_for_record(
        {
            "port": 80,
            "service": "http",
            "application_service": "apache",
            "banner": "Apache httpd 2.4.49",
        },
        include_vuln=True,
    )

    assert "http-git" in scripts
    assert "http-config-backup" in scripts
    assert "http-shellshock" in scripts
    assert "http-vuln-cve2014-3704" in scripts


def test_select_nse_scripts_returns_empty_for_unknown_service_without_aliases() -> None:
    scripts = select_nse_scripts_for_record(
        {
            "port": 1524,
            "service": "unknown",
            "application_service": None,
            "product_name": None,
            "banner": None,
        },
        include_vuln=True,
    )

    assert scripts == []


def test_parse_xml_output_normalizes_ftp_anon_and_http_methods() -> None:
    output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <script id="ftp-anon" output="Anonymous FTP login allowed&#10;-rw-r--r-- 1 ftp ftp 0 Jan 01 00:00 incoming"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <script id="http-methods" output="Supported Methods: GET HEAD POST OPTIONS&#10;Potentially risky methods: PUT DELETE"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = AsyncNmapScriptEnricher.parse_xml_output("10.10.0.20", output)

    assert parsed[21]["ftp-anon"]["hit"] is True
    assert parsed[21]["ftp-anon"]["anonymous_allowed"] is True
    assert parsed[21]["ftp-anon"]["listing"] == ["-rw-r--r-- 1 ftp ftp 0 Jan 01 00:00 incoming"]
    assert parsed[8080]["http-methods"]["hit"] is True
    assert parsed[8080]["http-methods"]["risky_methods"] == ["PUT", "DELETE"]
    assert "风险方法" in parsed[8080]["http-methods"]["summary"]


def test_parse_xml_output_normalizes_http_enum_and_struts_probe() -> None:
    output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.30" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <script id="http-enum" output="/manager/html: Apache Tomcat Manager&#10;/phpmyadmin/: phpMyAdmin"/>
        <script id="http-vuln-cve2017-5638" output="State: VULNERABLE&#10;Apache Struts Remote Code Execution Vulnerability"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = AsyncNmapScriptEnricher.parse_xml_output("10.10.0.30", output)

    assert parsed[8080]["http-enum"]["discovered_paths"] == ["/manager/html", "/phpmyadmin/"]
    assert parsed[8080]["http-enum"]["path_count"] == 2
    assert parsed[8080]["http-vuln-cve2017-5638"]["vulnerable"] is True
    assert parsed[8080]["http-vuln-cve2017-5638"]["state"] == "VULNERABLE"


def test_parse_xml_output_normalizes_git_backup_and_shellshock_results() -> None:
    output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.33" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <script id="http-git" output="/.git/HEAD: refs/heads/main"/>
        <script id="http-config-backup" output="/config.php.bak: PHP config&#10;/backup/settings.old: settings"/>
        <script id="http-shellshock" output="State: VULNERABLE&#10;Shellshock was detected"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = AsyncNmapScriptEnricher.parse_xml_output("10.10.0.33", output)

    assert parsed[80]["http-git"]["git_head_exposed"] is True
    assert parsed[80]["http-git"]["hit"] is True
    assert parsed[80]["http-config-backup"]["exposed_files"] == ["/backup/settings.old", "/config.php.bak"]
    assert parsed[80]["http-shellshock"]["vulnerable"] is True


def test_parse_xml_output_normalizes_ms17_010_host_script() -> None:
    output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="State: VULNERABLE&#10;Remote Code Execution vulnerability in Microsoft SMBv1 servers"/>
    </hostscript>
  </host>
</nmaprun>
"""

    parsed = AsyncNmapScriptEnricher.parse_xml_output(
        "10.10.0.34",
        output,
        requested_by_port={445: ["smb-vuln-ms17-010"]},
    )

    assert parsed[445]["smb-vuln-ms17-010"]["vulnerable"] is True
    assert parsed[445]["smb-vuln-ms17-010"]["hit"] is True


def test_parse_xml_output_maps_host_scripts_back_to_requested_port() -> None:
    output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.31" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-enum-shares" output="account_used: WORKGROUP\\\\guest&#10;IPC$&#10;  Anonymous access: READ&#10;  Current user access: READ&#10;public&#10;  Anonymous access: READ/WRITE&#10;  Current user access: READ/WRITE">
        <elem key="account_used">WORKGROUP\\guest</elem>
        <table key="IPC$">
          <elem key="Anonymous access">READ</elem>
          <elem key="Current user access">READ</elem>
        </table>
        <table key="public">
          <elem key="Anonymous access">READ/WRITE</elem>
          <elem key="Current user access">READ/WRITE</elem>
        </table>
      </script>
      <script id="smb-enum-users" output="Domain: LAB; Users: Administrator, Guest, backup"/>
    </hostscript>
  </host>
</nmaprun>
"""

    parsed = AsyncNmapScriptEnricher.parse_xml_output(
        "10.10.0.31",
        output,
        requested_by_port={445: ["smb-enum-shares", "smb-enum-users"]},
    )

    assert parsed[445]["smb-enum-shares"]["share_names"] == ["IPC$", "public"]
    assert parsed[445]["smb-enum-shares"]["anonymous_shares"] == ["IPC$", "public"]
    assert parsed[445]["smb-enum-shares"]["writable_shares"] == ["public"]
    assert parsed[445]["smb-enum-users"]["usernames"] == ["Administrator", "Guest", "backup"]
    assert parsed[445]["smb-enum-users"]["user_count"] == 3


def test_parse_xml_output_normalizes_ssh_auth_methods() -> None:
    output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.32" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <script id="ssh-auth-methods" output="Supported authentication methods:&#10;  publickey&#10;  password">
          <table key="Supported authentication methods">
            <elem>publickey</elem>
            <elem>password</elem>
          </table>
          <elem key="Banner">Authorized users only</elem>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = AsyncNmapScriptEnricher.parse_xml_output("10.10.0.32", output)

    assert parsed[22]["ssh-auth-methods"]["auth_methods"] == ["publickey", "password"]
    assert parsed[22]["ssh-auth-methods"]["banner"] == "Authorized users only"


def test_parse_xml_output_normalizes_heartbleed_result() -> None:
    output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.21" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <script id="ssl-heartbleed" output="State: VULNERABLE&#10;The Heartbleed Bug is a serious vulnerability"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = AsyncNmapScriptEnricher.parse_xml_output("10.10.0.21", output)

    assert parsed[443]["ssl-heartbleed"]["hit"] is True
    assert parsed[443]["ssl-heartbleed"]["vulnerable"] is True
    assert parsed[443]["ssl-heartbleed"]["state"] == "VULNERABLE"


def test_build_nse_summary_and_filter_results() -> None:
    results = {
        "ftp-anon": {
            "hit": True,
            "summary": "Anonymous FTP login allowed",
            "anonymous_allowed": True,
            "raw_output": "Anonymous FTP login allowed",
        },
        "ftp-syst": {
            "hit": False,
            "summary": "UNIX Type: L8",
            "system_type": "UNIX Type: L8",
            "raw_output": "UNIX Type: L8",
        },
    }

    summary = build_nse_summary(["ftp-anon", "ftp-syst"], results)
    filtered = filter_nse_results(results, {"ftp-anon"})

    assert summary["script_count"] == 2
    assert summary["hit_count"] == 1
    assert summary["hit_scripts"] == ["ftp-anon"]
    assert filtered["ftp-anon"]["anonymous_allowed"] is True
    assert "raw_output" not in filtered["ftp-anon"]
    assert "ftp-syst" not in filtered
