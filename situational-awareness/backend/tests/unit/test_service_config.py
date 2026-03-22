from app.collector.service_config import detect_collectable_services, parse_service_config


def test_detect_collectable_services_uses_services_and_packages() -> None:
    services = [
        {"name": "sshd", "state": "running", "enabled": None, "pid": None},
        {"name": "redis", "state": "running", "enabled": None, "pid": None},
    ]
    packages = [
        {"name": "tomcat9", "version": "9.0.30", "manager": "dpkg", "arch": "amd64"},
        {"name": "apache2", "version": "2.4.49", "manager": "dpkg", "arch": "amd64"},
    ]

    detected = detect_collectable_services(services, packages)

    assert detected == ["ssh", "redis", "tomcat", "apache"]


def test_parse_ssh_config_normalizes_boolean_keys() -> None:
    parsed = parse_service_config(
        "ssh",
        "passwordauthentication yes\npermitrootlogin prohibit-password\npubkeyauthentication no\npermitemptypasswords yes\n",
    )

    assert parsed == {
        "password_authentication": True,
        "permit_root_login": True,
        "pubkey_authentication": False,
        "permit_empty_passwords": True,
    }


def test_parse_ssh_and_mysql_config_extracts_source_files() -> None:
    ssh = parse_service_config(
        "ssh",
        "source_file=/etc/ssh/sshd_config\n/etc/ssh/sshd_config:PasswordAuthentication yes\n",
    )
    mysql = parse_service_config(
        "mysql",
        "source_file=/etc/mysql/my.cnf\n/etc/mysql/my.cnf:local_infile = ON\n",
    )

    assert ssh["source_files"] == ["/etc/ssh/sshd_config"]
    assert mysql["source_files"] == ["/etc/mysql/my.cnf"]
    assert mysql["local_infile"] is True


def test_parse_redis_config_extracts_bind_and_auth() -> None:
    parsed = parse_service_config(
        "redis",
        'bind 0.0.0.0 ::\nprotected-mode no\nrequirepass ""\n',
    )

    assert parsed == {
        "bind_all_interfaces": True,
        "protected_mode": False,
        "requirepass": "",
    }


def test_parse_vsftpd_config_extracts_anonymous_flags() -> None:
    parsed = parse_service_config(
        "vsftpd",
        "anonymous_enable=YES\nwrite_enable=YES\nanon_upload_enable=YES\n",
    )

    assert parsed == {
        "anonymous_enabled": True,
        "anonymous_write_enabled": True,
    }


def test_parse_samba_config_extracts_guest_and_writable_share() -> None:
    parsed = parse_service_config(
        "samba",
        "map to guest = Bad User\nguest ok = yes\nwritable = yes\n",
    )

    assert parsed == {
        "guest_access": True,
        "writable_guest_share": True,
    }


def test_parse_tomcat_config_extracts_flags() -> None:
    parsed = parse_service_config(
        "tomcat",
        "manager_exposed=true\nsample_apps_enabled=true\ndefault_credentials=true\n",
    )

    assert parsed == {
        "manager_exposed": True,
        "sample_apps_enabled": True,
        "default_credentials": True,
    }


def test_parse_apache_and_nginx_configs_extract_http_flags() -> None:
    apache = parse_service_config("apache", "Options Indexes FollowSymLinks\nDav On\n")
    nginx = parse_service_config("nginx", "autoindex on;\ndav_methods PUT DELETE MKCOL;\n")

    assert apache == {
        "directory_listing_enabled": True,
        "webdav_enabled": True,
    }
    assert nginx == {
        "directory_listing_enabled": True,
        "webdav_enabled": True,
    }


def test_parse_postgresql_config_extracts_auth_and_listener_flags() -> None:
    parsed = parse_service_config(
        "postgresql",
        "host all all 0.0.0.0/0 trust\nlisten_addresses = '*'\n",
    )

    assert parsed == {
        "trust_auth_enabled": True,
        "listen_all_interfaces": True,
    }


def test_detect_collectable_services_includes_mysql_by_service_alias() -> None:
    services = [
        {"name": "mysqld", "state": "running", "enabled": None, "pid": None},
    ]

    detected = detect_collectable_services(services, [])

    assert detected == ["mysql"]


def test_parse_mysql_config_extracts_risky_flags() -> None:
    parsed = parse_service_config(
        "mysql",
        "skip-grant-tables\nlocal_infile = ON\nbind-address = 0.0.0.0\n",
    )

    assert parsed == {
        "skip_grant_tables": True,
        "local_infile": True,
        "bind_all_interfaces": True,
    }
