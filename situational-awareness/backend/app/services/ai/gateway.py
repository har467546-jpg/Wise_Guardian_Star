from app.core.config import settings
from app.services.ai.providers import BaseProvider, LLMRequest, MockProvider, build_provider


class LLMGateway:
    def __init__(self) -> None:
        self.provider: BaseProvider = self._build_provider()

    def _build_provider(self) -> BaseProvider:
        result = build_provider(
            provider_name=str(settings.LLM_PROVIDER or "mock"),
            api_key=str(settings.LLM_API_KEY or ""),
            model=str(settings.LLM_MODEL or "gpt-4o-mini"),
            base_url=str(settings.LLM_BASE_URL or ""),
            wire_api=str(settings.LLM_WIRE_API or "responses"),
            timeout_seconds=int(settings.LLM_TIMEOUT_SECONDS or 60),
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
