from app.scanner.service_fingerprint import fingerprint_service, infer_service_aliases, infer_service_versions


def test_fingerprint_ssh_banner() -> None:
    result = fingerprint_service(22, "SSH-2.0-OpenSSH_8.9p1 Debian-3")
    assert result.service == "ssh"
    assert result.product_name == "openssh"
    assert result.version == "8.9"
    assert result.hostname_hint is None


def test_fingerprint_http_banner_extracts_application_and_location_hostname() -> None:
    banner = (
        "HTTP/1.1 302 Found\r\n"
        "Server: nginx/1.24.0\r\n"
        "Location: https://app.lab.example/login\r\n"
        "\r\n"
    )
    result = fingerprint_service(80, banner)
    assert result.service == "nginx"
    assert result.transport_service == "http"
    assert result.application_service == "nginx"
    assert result.version == "1.24.0"
    assert result.hostname_hint == "app.lab.example"


def test_fingerprint_https_prefers_certificate_hostname() -> None:
    banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.22.1\r\n\r\n"
    result = fingerprint_service(443, banner, certificate_names=["gateway.lab.example", "10.0.0.8"])
    assert result.service == "nginx"
    assert result.transport_service == "https"
    assert result.tls_detected is True
    assert result.version == "1.22.1"
    assert result.hostname_hint == "gateway.lab.example"


def test_fingerprint_redis_banner() -> None:
    result = fingerprint_service(6379, "+PONG\r\n")
    assert result.service == "redis"
    assert result.product_name == "redis"
    assert result.version is None


def test_fingerprint_mysql_banner() -> None:
    banner = "\x4a\x00\x00\x00\x0a8.0.35\x00mysql-native-password\x00"
    result = fingerprint_service(3306, banner)
    assert result.service == "mysql"
    assert result.product_name == "mysql"
    assert result.version == "8.0.35"


def test_fingerprint_ftp_banner_identifies_vsftpd() -> None:
    result = fingerprint_service(21, "220 (vsFTPd 3.0.3)\r\n")
    assert result.transport_service == "ftp"
    assert result.application_service == "vsftpd"
    assert result.service == "vsftpd"
    assert result.product_name == "vsftpd"
    assert result.version == "3.0.3"


def test_fingerprint_ftp_banner_is_not_misclassified_as_smtp() -> None:
    result = fingerprint_service(21, "220 FTP server ready\r\n")
    assert result.transport_service == "ftp"
    assert result.service == "ftp"
    assert result.product_name == "ftp"


def test_fingerprint_smtp_pop3_imap_and_memcached_banners() -> None:
    smtp = fingerprint_service(25, "220 mail.lab.example ESMTP Postfix\r\n")
    pop3 = fingerprint_service(110, "+OK POP3 ready <123@example>\r\n")
    imap = fingerprint_service(143, "* OK IMAP4 ready\r\n")
    memcached = fingerprint_service(11211, "VERSION 1.6.21\r\n")

    assert smtp.service == "smtp"
    assert smtp.product_name == "postfix"
    assert pop3.service == "pop3"
    assert imap.service == "imap"
    assert memcached.service == "memcached"
    assert memcached.version == "1.6.21"


def test_fingerprint_http_json_identifies_elasticsearch() -> None:
    banner = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"name":"node-1","cluster_name":"lab","version":{"number":"8.12.1"},"tagline":"You Know, for Search"}'
    )
    result = fingerprint_service(9200, banner)
    assert result.service == "elasticsearch"
    assert result.product_name == "elasticsearch"
    assert result.version == "8.12.1"


def test_fingerprint_http_phpmyadmin_does_not_reuse_apache_server_version() -> None:
    banner = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.2.8\r\n"
        "X-Powered-By: PHP/5.2.4\r\n"
        "\r\n"
        "<html><head><title>phpMyAdmin</title></head><body></body></html>"
    )
    result = fingerprint_service(80, banner)

    assert result.service == "phpmyadmin"
    assert result.product_name == "phpmyadmin"
    assert result.version is None


def test_infer_service_aliases_expands_phpmyadmin_to_apache_php_and_http() -> None:
    aliases = infer_service_aliases(
        {
            "port": 80,
            "service": "phpmyadmin",
            "application_service": "phpmyadmin",
            "product_name": "phpmyadmin",
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.2.8\r\nX-Powered-By: PHP/5.2.4\r\n\r\n",
        }
    )

    assert "phpmyadmin" in aliases
    assert "apache" in aliases
    assert "php" in aliases
    assert "http" in aliases


def test_infer_service_versions_extracts_tomcat_from_nse_http_title() -> None:
    versions = infer_service_versions(
        {
            "port": 8180,
            "service": "unknown",
            "nse": {
                "http-title": {"title": "Apache Tomcat/5.5"},
                "http-headers": {"headers": {"server": "Apache-Coyote/1.1"}},
            },
        }
    )

    assert versions["tomcat"] == "5.5"
    assert "apache" not in versions


def test_fingerprint_service_uses_tomcat_title_instead_of_apache_coyote_connector_version() -> None:
    banner = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache-Coyote/1.1\r\n"
        "\r\n"
        "<html><head><title>Apache Tomcat/5.5</title></head><body></body></html>"
    )
    result = fingerprint_service(8180, banner)

    assert result.service == "tomcat"
    assert result.version == "5.5"


def test_fingerprint_service_does_not_emit_tomcat_1_1_from_apache_coyote_alone() -> None:
    result = fingerprint_service(8180, "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\n")

    assert result.service == "tomcat"
    assert result.version is None


def test_infer_service_aliases_does_not_confuse_apache_coyote_with_apache_httpd() -> None:
    aliases = infer_service_aliases(
        {
            "port": 8180,
            "service": "unknown",
            "nse": {
                "http-title": {"title": "Apache Tomcat/5.5"},
                "http-headers": {"headers": {"server": "Apache-Coyote/1.1"}},
            },
        }
    )

    assert "tomcat" in aliases
    assert "apache" not in aliases


def test_fingerprint_service_uses_distccd_port_hint() -> None:
    result = fingerprint_service(3632, None)

    assert result.service == "distccd"
    assert "distccd" in result.service_aliases


def test_fingerprint_service_uses_rpcbind_port_hint() -> None:
    result = fingerprint_service(111, None)

    assert result.service == "rpcbind"
    assert "rpcbind" in result.service_aliases


def test_fingerprint_service_uses_rmi_ajp_and_exec_port_hints() -> None:
    rmi = fingerprint_service(1099, None)
    ajp = fingerprint_service(8009, None)
    rexec = fingerprint_service(512, None)
    rlogin = fingerprint_service(513, None)
    rsh = fingerprint_service(514, None)

    assert rmi.service == "java-rmi"
    assert ajp.service == "ajp13"
    assert rexec.service == "rexec"
    assert rlogin.service == "rlogin"
    assert rsh.service == "rsh"
