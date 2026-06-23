from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROUTER_PATH = ROOT / "backend" / "app" / "api" / "v1" / "router.py"
API_DOC_PATH = ROOT / "docs" / "api-contract.md"
BACKEND_DOC_PATH = ROOT / "docs" / "backend-design.md"


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_router_groups(text: str) -> set[str]:
    return set(re.findall(r'include_router\([^,]+,\s*prefix="/([^"]+)"', text))


def _extract_doc_groups(text: str) -> set[str]:
    return set(re.findall(r"`/([a-z0-9-]+)`", text))


def main() -> int:
    router_groups = _extract_router_groups(_read_text(ROUTER_PATH))
    api_doc_groups = _extract_doc_groups(_read_text(API_DOC_PATH))
    backend_doc_text = _read_text(BACKEND_DOC_PATH)

    missing_in_api_doc = sorted(router_groups - api_doc_groups)
    stale_backend_doc = "未挂载到 `api_router`" in backend_doc_text and "reports.py" in backend_doc_text

    failed = False
    if missing_in_api_doc:
      failed = True
      print("Missing API doc groups:", ", ".join(missing_in_api_doc))
    if stale_backend_doc:
      failed = True
      print("backend-design.md still contains stale reports route note")

    if failed:
      return 1
    print("API docs are in sync with mounted router groups.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
