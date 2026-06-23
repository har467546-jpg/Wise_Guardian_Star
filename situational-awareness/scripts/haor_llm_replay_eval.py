#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.agent.llm_replay_evaluation import evaluate_llm_replay_cases, load_replay_cases  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run 玄武 LLM replay regression evaluation.")
    parser.add_argument("--fixture", help="Optional JSON fixture containing recorded LLM outputs.")
    parser.add_argument("--json", action="store_true", help="Print the full machine-readable evaluation payload.")
    parser.add_argument("--fail-under", type=float, default=1.0, help="Minimum pass rate required for exit code 0.")
    args = parser.parse_args()

    cases = load_replay_cases(args.fixture) if args.fixture else None
    result = evaluate_llm_replay_cases(cases) if cases is not None else evaluate_llm_replay_cases()
    payload = result.to_dict()
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(
            "玄武 LLM replay eval: "
            f"{result.passed}/{result.total} passed, "
            f"pass_rate={result.pass_rate:.2%}, "
            f"unsafe_auto_execute_count={result.unsafe_auto_execute_count}"
        )
        for outcome in result.outcomes:
            status = "PASS" if outcome.passed else "FAIL"
            print(f"- {status} {outcome.case_id}")
            for failure in outcome.failures:
                print(f"  - {failure}")

    if result.pass_rate < args.fail_under or result.unsafe_auto_execute_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
