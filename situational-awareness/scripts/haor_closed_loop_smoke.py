#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

import jwt


TERMINAL_TASK_STATUSES = {"success", "failure", "canceled"}


@dataclass
class SmokeResult:
    name: str
    success: bool
    detail: str


class ApiClient:
    def __init__(self, *, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def request(self, method: str, path: str, data: dict | None = None) -> tuple[int, dict]:
        body = None if data is None else json.dumps(data).encode()
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            method=method,
            data=body,
            headers=self.headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                raw = resp.read().decode()
                return resp.status, json.loads(raw or "null")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            try:
                payload = json.loads(raw)
            except Exception:
                payload = {"detail": raw}
            return exc.code, payload


def _build_token(*, user_id: str, secret: str) -> str:
    payload = {
        "sub": user_id,
        "role": "ADMIN",
        "exp": dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=8),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _expect(status: int, expected: int, detail: str) -> None:
    if status != expected:
        raise AssertionError(f"{detail}: expected {expected}, got {status}")


def _wait_for_task(client: ApiClient, *, task_id: str, timeout_seconds: int = 240) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        status, payload = client.request("GET", f"/tasks/{task_id}")
        _expect(status, 200, f"读取任务 {task_id} 失败")
        if str(payload.get("status") or "").strip().lower() in TERMINAL_TASK_STATUSES:
            return payload
        time.sleep(1.5)
    raise AssertionError(f"等待任务 {task_id} 超时")


def _wait_for_session_message(
    client: ApiClient,
    *,
    predicate,
    timeout_seconds: int = 240,
) -> tuple[dict, dict]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        status, session = client.request("GET", "/agent/haor/session")
        _expect(status, 200, "读取玄武会话失败")
        messages = session.get("messages") or []
        if messages:
            last = messages[-1]
            if predicate(last, session):
                return session, last
        time.sleep(1.5)
    raise AssertionError("等待玄武会话消息超时")


def _message_content(message: dict) -> str:
    return str(message.get("content") or "")


def _runtime_snapshot(session: dict) -> dict:
    return session.get("runtime_snapshot") or {}


def scenario_scan_and_followup(client: ApiClient, *, cidr: str) -> SmokeResult:
    status, _ = client.request("POST", "/agent/haor/session/reset", {})
    _expect(status, 200, "重置玄武会话失败")

    status, session = client.request(
        "POST",
        "/agent/haor/session/messages",
        {
            "content": f"帮我扫描 {cidr} 网段，并实时告诉我进度",
            "page_context": {"pathname": "/discovery", "query": {}},
            "browser_context": {"pathname": "/discovery", "query": {}},
        },
    )
    _expect(status, 200, "发起扫描失败")
    task_id = str(session.get("last_task_id") or _runtime_snapshot(session).get("watch_task_id") or "").strip()
    if not task_id:
        raise AssertionError("扫描链路没有生成可跟踪任务")

    task = _wait_for_task(client, task_id=task_id, timeout_seconds=360)
    if task.get("status") != "success":
        raise AssertionError(f"扫描任务未成功完成: {task.get('message')}")

    status, followup = client.request(
        "POST",
        "/agent/haor/session/messages",
        {
            "content": "继续分析扫描结果",
            "page_context": {"pathname": "/discovery", "query": {}},
            "browser_context": {"pathname": "/discovery", "query": {}},
        },
    )
    _expect(status, 200, "扫描完成后的继续承接失败")
    last = (followup.get("messages") or [])[-1]
    if last.get("message_type") != "text":
        raise AssertionError(f"扫描结果承接未收敛成文本总结: {last.get('message_type')} / {_message_content(last)}")
    return SmokeResult("scan_and_followup", True, f"扫描任务 {task_id} 成功，继续承接消息类型为 {last.get('message_type')}")


def scenario_verify_and_followup(client: ApiClient, *, asset_id: str) -> SmokeResult:
    status, _ = client.request("POST", "/agent/haor/session/reset", {})
    _expect(status, 200, "重置玄武会话失败")

    status, session = client.request(
        "POST",
        "/agent/haor/session/messages",
        {
            "content": "请验证当前资产的风险",
            "page_context": {"pathname": f"/assets/{asset_id}", "asset_id": asset_id, "query": {}},
            "browser_context": {"pathname": f"/assets/{asset_id}", "asset_id": asset_id, "query": {}},
        },
    )
    _expect(status, 200, "触发风险验证失败")
    task_id = str(session.get("last_task_id") or _runtime_snapshot(session).get("watch_task_id") or "").strip()
    if not task_id:
        raise AssertionError("风险验证没有生成任务")

    task = _wait_for_task(client, task_id=task_id)
    if task.get("status") != "success":
        raise AssertionError(f"风险验证未成功完成: {task.get('message')}")

    status, followup = client.request(
        "POST",
        "/agent/haor/session/messages",
        {
            "content": "继续分析验证结果",
            "page_context": {"pathname": f"/assets/{asset_id}", "asset_id": asset_id, "query": {}},
            "browser_context": {"pathname": f"/assets/{asset_id}", "asset_id": asset_id, "query": {}},
        },
    )
    _expect(status, 200, "验证结果承接失败")
    last = (followup.get("messages") or [])[-1]
    if last.get("message_type") == "error":
        raise AssertionError(f"验证结果承接出现错误: {_message_content(last)}")
    return SmokeResult("verify_and_followup", True, f"验证任务 {task_id} 成功，继续承接消息类型为 {last.get('message_type')}")


def scenario_remediation_with_maintenance_window(client: ApiClient, *, asset_id: str, maintenance_window_id: str) -> SmokeResult:
    status, _ = client.request("POST", "/agent/haor/session/reset", {})
    _expect(status, 200, "重置玄武会话失败")

    page_context = {"pathname": f"/assets/{asset_id}", "asset_id": asset_id, "query": {}}
    status, session = client.request(
        "POST",
        "/agent/haor/session/messages",
        {
            "content": "请为当前资产生成修复计划，如果适合就继续自动修复",
            "page_context": page_context,
            "browser_context": page_context,
        },
    )
    _expect(status, 200, "发起自动修复计划失败")
    if session.get("status") != "waiting_approval":
        raise AssertionError(f"修复计划未进入待审批: {session.get('status')}")

    status, approve = client.request("POST", "/agent/haor/session/approve", {"note": "玄武 smoke approve 1"})
    _expect(status, 202, "首次批准修复计划失败")
    orchestrate_task_id = str(approve.get("task_id") or "").strip()
    if not orchestrate_task_id:
        raise AssertionError("首次批准未返回编排任务 ID")

    _wait_for_task(client, task_id=orchestrate_task_id)
    session_after_block, blocked_message = _wait_for_session_message(
        client,
        predicate=lambda message, _session: (
            message.get("message_type") == "action_update"
            and "maintenance_window_id" in _message_content(message)
        ),
    )
    payload = blocked_message.get("payload_json") or {}
    if not payload.get("recommended_action"):
        raise AssertionError("维护窗口阻塞未给出推荐动作")
    if _runtime_snapshot(session_after_block).get("input_state") != "enabled":
        raise AssertionError("维护窗口阻塞后输入未恢复可用")

    status, resumed = client.request(
        "POST",
        "/agent/haor/session/messages",
        {
            "content": f"maintenance_window_id 是 {maintenance_window_id}，请继续自动修复",
            "page_context": page_context,
            "browser_context": page_context,
        },
    )
    _expect(status, 200, "补充维护窗口 ID 失败")
    pending_plan = resumed.get("pending_plan_json") or {}
    actions = pending_plan.get("proposed_write_actions") or []
    if not actions:
        raise AssertionError("补充维护窗口后没有新的待确认计划")
    params = actions[0].get("params") if isinstance(actions[0].get("params"), dict) else {}
    if params.get("maintenance_window_id") != maintenance_window_id:
        raise AssertionError("维护窗口 ID 没有写回待确认计划")

    status, approve2 = client.request("POST", "/agent/haor/session/approve", {"note": "玄武 smoke approve 2"})
    _expect(status, 202, "带维护窗口的修复批准失败")
    orchestrate_task_id_2 = str(approve2.get("task_id") or "").strip()
    if not orchestrate_task_id_2:
        raise AssertionError("第二次批准未返回编排任务 ID")

    _wait_for_task(client, task_id=orchestrate_task_id_2, timeout_seconds=480)
    session_terminal, terminal_message = _wait_for_session_message(
        client,
        predicate=lambda message, _session: (
            message.get("message_type") in {"task_update", "error"}
            and (
                "自动修复任务已完成" in _message_content(message)
                or "自动修复任务未成功完成" in _message_content(message)
            )
        ),
        timeout_seconds=480,
    )
    runtime = _runtime_snapshot(session_terminal)
    if runtime.get("input_state") != "enabled":
        raise AssertionError("修复终态后输入未恢复可用")

    status, review = client.request(
        "POST",
        "/agent/haor/session/messages",
        {
            "content": "继续，复盘这次自动修复结果",
            "page_context": page_context,
            "browser_context": page_context,
        },
    )
    _expect(status, 200, "修复复盘承接失败")
    last = (review.get("messages") or [])[-1]
    if last.get("message_type") != "text":
        raise AssertionError(f"复盘结果未收敛成文本回答: {last.get('message_type')}")
    if review.get("pending_plan_json"):
        raise AssertionError("复盘后仍然出现新的待确认计划")
    if _runtime_snapshot(review).get("input_state") != "enabled":
        raise AssertionError("复盘后输入未保持可用")

    return SmokeResult(
        "remediation_with_maintenance_window",
        True,
        f"阻塞->补维护窗口->修复->{last.get('message_type')} 复盘均通过；终态消息为 {terminal_message.get('message_type')}",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run 玄武 closed-loop smoke tests against a live local stack.")
    parser.add_argument("--base-url", default="http://localhost:8000/api/v1")
    parser.add_argument("--user-id", default="user-1")
    parser.add_argument("--jwt-secret", default="change-this-secret")
    parser.add_argument("--cidr", default="192.168.130.0/24")
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--maintenance-window-id", default="mw-haor-smoke")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = _build_token(user_id=args.user_id, secret=args.jwt_secret)
    client = ApiClient(base_url=args.base_url, token=token)

    scenarios = [
        lambda: scenario_scan_and_followup(client, cidr=args.cidr),
        lambda: scenario_verify_and_followup(client, asset_id=args.asset_id),
        lambda: scenario_remediation_with_maintenance_window(
            client,
            asset_id=args.asset_id,
            maintenance_window_id=args.maintenance_window_id,
        ),
    ]

    results: list[SmokeResult] = []
    for scenario in scenarios:
        try:
            result = scenario()
        except Exception as exc:
            name = getattr(scenario, "__name__", "scenario")
            results.append(SmokeResult(name=name, success=False, detail=str(exc)))
            break
        else:
            results.append(result)

    print(json.dumps([result.__dict__ for result in results], ensure_ascii=False, indent=2))
    return 0 if results and all(result.success for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
