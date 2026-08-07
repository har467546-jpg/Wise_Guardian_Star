from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.ai import model_pool_service
from app.services.ai import model_router_service
from app.services import rate_limit_service


@pytest.fixture(autouse=True)
def _isolate_rate_limit_state(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    rate_limit_service._local_windows.clear()
    safe_nodeid = "".join(ch if ch.isalnum() else "_" for ch in request.node.nodeid)[-120:]
    monkeypatch.setattr(settings, "RATE_LIMIT_REDIS_PREFIX", f"sa:test_rate_limit:{safe_nodeid}")
    monkeypatch.setattr(settings, "LLM_MODEL_POOL_REDIS_PREFIX", f"sa:test_model_pool:{safe_nodeid}")
    monkeypatch.setattr(settings, "AI_GATEWAY_REDIS_PREFIX", f"sa:test_ai_gateway:{safe_nodeid}")
    monkeypatch.setattr(settings, "HAOR_REPLY_REWRITE_ENABLED", False)
    model_pool_service.reset_local_model_pool_state()
    model_router_service.reset_local_gateway_state()
    yield
    rate_limit_service._local_windows.clear()
    model_pool_service.reset_local_model_pool_state()
    model_router_service.reset_local_gateway_state()
