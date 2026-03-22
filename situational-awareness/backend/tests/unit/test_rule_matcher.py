from app.rules.rule_matcher import PackageMatchDefinition, RuleDefinition, RuleInput, RuleMatcher


RULES = [
    RuleDefinition(
        rule_id="nginx.version.lt_1_18",
        enabled=True,
        service="nginx",
        severity="high",
        description="nginx version is older than 1.18",
        version_constraint="<1.18",
    ),
    RuleDefinition(
        rule_id="redis.auth.disabled",
        enabled=True,
        service="redis",
        severity="critical",
        description="redis authentication is not enabled",
        config_conditions={"requirepass": {"exists": False}},
    ),
    RuleDefinition(
        rule_id="redis.auth.empty",
        enabled=True,
        service="redis",
        severity="critical",
        description="redis authentication is configured with an empty password",
        config_conditions={"requirepass": {"eq": ""}},
    ),
    RuleDefinition(
        rule_id="ssh.password_login.enabled",
        enabled=True,
        service="ssh",
        severity="medium",
        description="ssh password login is enabled",
        config_conditions={"password_authentication": {"eq": True}},
    ),
    RuleDefinition(
        rule_id="ftp.anonymous.nse.enabled",
        enabled=True,
        service="vsftpd",
        severity="high",
        description="ftp anonymous login allowed",
        nse_conditions={"ftp-anon.hit": {"eq": True}},
    ),
]


def test_rule_matcher_matches_version_constraint() -> None:
    matches = RuleMatcher.match(RuleInput(service="nginx", version="nginx/1.16.1"), RULES)
    assert [item.rule_id for item in matches] == ["nginx.version.lt_1_18"]


def test_rule_matcher_skips_invalid_version_and_non_matching_service() -> None:
    assert RuleMatcher.match(RuleInput(service="nginx", version="latest"), RULES) == []
    assert RuleMatcher.match(RuleInput(service="mysql", version="5.6"), RULES) == []


def test_rule_matcher_matches_multiple_config_rules() -> None:
    matches = RuleMatcher.match(RuleInput(service="redis", config={"requirepass": ""}), RULES)
    assert {item.rule_id for item in matches} == {"redis.auth.empty"}

    matches = RuleMatcher.match(RuleInput(service="redis", config={}), RULES)
    assert {item.rule_id for item in matches} == {"redis.auth.disabled"}


def test_rule_matcher_matches_boolean_config() -> None:
    matches = RuleMatcher.match(RuleInput(service="ssh", config={"password_authentication": True}), RULES)
    assert [item.rule_id for item in matches] == ["ssh.password_login.enabled"]


def test_rule_matcher_supports_composite_version_ranges() -> None:
    rules = [
        RuleDefinition(
            rule_id="openssh.user_enumeration.gte_4_8_lt_7_7",
            enabled=True,
            service="ssh",
            severity="high",
            description="OpenSSH username enumeration risk",
            version_constraint=">=4.8,<7.7",
        )
    ]

    matches = RuleMatcher.match(RuleInput(service="ssh", version="OpenSSH_7.2p2 Ubuntu"), rules)
    assert [item.rule_id for item in matches] == ["openssh.user_enumeration.gte_4_8_lt_7_7"]

    misses = RuleMatcher.match(RuleInput(service="ssh", version="OpenSSH_8.8"), rules)
    assert misses == []


def test_rule_matcher_matches_nse_conditions() -> None:
    matches = RuleMatcher.match(
        RuleInput(
            service="vsftpd",
            nse={
                "ftp-anon": {
                    "hit": True,
                    "anonymous_allowed": True,
                }
            },
        ),
        RULES,
    )
    assert [item.rule_id for item in matches] == ["ftp.anonymous.nse.enabled"]


def test_rule_matcher_normalizes_epoch_and_patch_suffix_versions() -> None:
    assert RuleMatcher._normalize_version("1:1.8.31-1ubuntu1.5") == "1.8.31"
    assert RuleMatcher._normalize_version("OpenSSH_7.2p2 Ubuntu-4ubuntu2.10") == "7.2.post2"


def test_rule_matcher_enforces_and_semantics_across_match_types() -> None:
    rules = [
        RuleDefinition(
            rule_id="vsftpd.backdoor.nse.confirmed",
            enabled=True,
            service="vsftpd",
            severity="critical",
            description="vsftpd backdoor confirmed by NSE",
            version_constraint="==2.3.4",
            nse_conditions={"ftp-vsftpd-backdoor.vulnerable": {"eq": True}},
        )
    ]

    matched = RuleMatcher.match(
        RuleInput(
            service="vsftpd",
            version="vsftpd 2.3.4",
            nse={"ftp-vsftpd-backdoor": {"vulnerable": True}},
        ),
        rules,
    )
    missed = RuleMatcher.match(
        RuleInput(
            service="vsftpd",
            version="vsftpd 2.3.4",
            nse={"ftp-vsftpd-backdoor": {"vulnerable": False}},
        ),
        rules,
    )

    assert [item.rule_id for item in matched] == ["vsftpd.backdoor.nse.confirmed"]
    assert missed == []


def test_rule_matcher_matches_distro_aware_package_conditions() -> None:
    rules = [
        RuleDefinition(
            rule_id="sudo.baron_samedit.cve_2021_3156.exposed",
            enabled=True,
            service="sudo",
            severity="critical",
            description="sudo vulnerable on ubuntu 20.04",
            package_conditions=PackageMatchDefinition(
                manager="dpkg",
                name="sudo",
                compare="lt_fixed",
                fixed_versions={
                    "ubuntu": {"20.04": "1.8.31-1ubuntu1.2"},
                    "debian": {"11": "1.9.5p2-3+deb11u1"},
                },
            ),
        )
    ]

    matched = RuleMatcher.match(
        RuleInput(
            service="sudo",
            package={
                "manager": "dpkg",
                "name": "sudo",
                "version": "1:1.8.31-1ubuntu1.1",
                "distro": "ubuntu",
                "release": "20.04",
            },
        ),
        rules,
    )
    missed = RuleMatcher.match(
        RuleInput(
            service="sudo",
            package={
                "manager": "dpkg",
                "name": "sudo",
                "version": "1:1.8.31-1ubuntu1.2",
                "distro": "ubuntu",
                "release": "20.04",
            },
        ),
        rules,
    )

    assert [item.rule_id for item in matched] == ["sudo.baron_samedit.cve_2021_3156.exposed"]
    assert missed == []


def test_rule_matcher_skips_package_match_without_release_context() -> None:
    rules = [
        RuleDefinition(
            rule_id="polkit.pwnkit.cve_2021_4034.exposed",
            enabled=True,
            service="polkit",
            severity="critical",
            description="polkit vulnerable",
            package_conditions=PackageMatchDefinition(
                manager="dpkg",
                name="policykit-1",
                compare="lt_fixed",
                fixed_versions={"debian": {"11": "0.105-31+deb11u1"}},
            ),
        )
    ]

    matches = RuleMatcher.match(
        RuleInput(
            service="polkit",
            package={
                "manager": "dpkg",
                "name": "policykit-1",
                "version": "0.105-31+deb11u0",
                "distro": "debian",
                "release": "",
            },
        ),
        rules,
    )

    assert matches == []
