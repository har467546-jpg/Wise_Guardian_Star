from __future__ import annotations

import json
from typing import Any

from app.utils.sanitize import sanitize_json_value, sanitize_text


def build_reflection_instruction(reflection_errors: list[dict[str, Any]]) -> str:
    latest_error = reflection_errors[-1] if reflection_errors else {}
    return (
        "上一次输出没有满足平台 JSON 契约，请立即自我修正。"
        "只能返回一个合法 JSON 对象，不要解释错误，不要输出 Markdown 代码块。"
        "修正时必须保留当前用户目标，并遵守 output_schema 与白名单动作边界。\n"
        "结构化错误摘要如下：\n"
        + json.dumps(
            sanitize_json_value(
                {
                    "attempt": len(reflection_errors),
                    "error": sanitize_text(str(latest_error.get("error") or ""), max_length=500) or "unknown",
                    "raw_response_preview": sanitize_text(str(latest_error.get("raw_response_preview") or ""), max_length=800)
                    or "",
                }
            ),
            ensure_ascii=False,
            indent=2,
        )
    )
