from __future__ import annotations

import pytest

from app.core.config import settings
from app.services import rate_limit_service


@pytest.fixture(autouse=True)
def _isolate_rate_limit_state(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    rate_limit_service._local_windows.clear()
    safe_nodeid = "".join(ch if ch.isalnum() else "_" for ch in request.node.nodeid)[-120:]
    monkeypatch.setattr(settings, "RATE_LIMIT_REDIS_PREFIX", f"sa:test_rate_limit:{safe_nodeid}")
    monkeypatch.setattr(settings, "HAOR_REPLY_REWRITE_ENABLED", False)
    yield
    rate_limit_service._local_windows.clear()
