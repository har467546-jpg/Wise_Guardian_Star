from app.core.config import read_runtime_env_value, settings
from app.services.ai.providers import BaseProvider, LLMRequest, MockProvider, build_provider


class LLMGateway:
    def __init__(self) -> None:
        self.provider: BaseProvider = self._build_provider()

    def _build_provider(self) -> BaseProvider:
        provider_name = read_runtime_env_value("LLM_PROVIDER", str(settings.LLM_PROVIDER or "mock"))
        api_key = read_runtime_env_value("LLM_API_KEY", str(settings.LLM_API_KEY or ""))
        model = read_runtime_env_value("LLM_MODEL", str(settings.LLM_MODEL or "gpt-4o-mini"))
        base_url = read_runtime_env_value("LLM_BASE_URL", str(settings.LLM_BASE_URL or ""))
        wire_api = read_runtime_env_value("LLM_WIRE_API", str(settings.LLM_WIRE_API or "responses"))
        timeout_seconds = int(read_runtime_env_value("LLM_TIMEOUT_SECONDS", str(settings.LLM_TIMEOUT_SECONDS or 60)) or 60)
        result = build_provider(
            provider_name=provider_name,
            api_key=api_key,
            model=model,
            base_url=base_url,
            wire_api=wire_api,
            timeout_seconds=timeout_seconds,
            fallback_to_mock=True,
        )
        return result.provider

    def summarize(self, prompt: str) -> str:
        request = LLMRequest.from_text(prompt)
        try:
            return self.provider.generate(request)
        except Exception as exc:
            fallback = MockProvider(f"AI 调用失败，已回退到模板摘要。原因: {exc}")
            return fallback.generate(request)
