from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.verifiers.base import VerificationContext, VerificationResult
from app.verifiers.detectors import (
    verify_distccd_rce_probe,
    verify_ftp_anonymous_login,
    verify_http_risky_methods_probe,
    verify_redis_unauth_info_probe,
    verify_tomcat_manager_default_creds,
    verify_unrealircd_backdoor_probe,
    verify_vsftpd_smiley_backdoor,
)

Verifier = Callable[[VerificationContext], Awaitable[VerificationResult]]


VERIFIER_REGISTRY: dict[str, Verifier] = {
    "vsftpd_smiley_backdoor": verify_vsftpd_smiley_backdoor,
    "ftp_anonymous_login": verify_ftp_anonymous_login,
    "tomcat_manager_default_creds": verify_tomcat_manager_default_creds,
    "distccd_rce_probe": verify_distccd_rce_probe,
    "unrealircd_backdoor_probe": verify_unrealircd_backdoor_probe,
    "redis_unauth_info_probe": verify_redis_unauth_info_probe,
    "http_risky_methods_probe": verify_http_risky_methods_probe,
}


def get_verifier(detector: str) -> Verifier | None:
    return VERIFIER_REGISTRY.get(detector)
