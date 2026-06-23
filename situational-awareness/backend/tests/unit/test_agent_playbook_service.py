from app.services.agent_playbook_service import (
    PLAYBOOK_ANALYZE_ASSET_RISKS,
    PLAYBOOK_INSTALL_RUNNER,
    PLAYBOOK_QUICK_SMALLTALK,
    PLAYBOOK_SCAN_AND_ANALYZE_CIDR,
    PLAYBOOK_START_REMEDIATION_SESSION,
    PLAYBOOK_VERIFY_ASSET_RISKS,
    infer_goal_profile,
    match_registered_playbook,
)


def test_infer_goal_profile_recognizes_scan_and_analyze_cidr() -> None:
    profile = infer_goal_profile(
        content="帮我扫描并分析 10.10.0.0/24 的风险",
        page_context={"pathname": "/discovery"},
        working_context={},
    )

    assert profile["goal_kind"] == PLAYBOOK_SCAN_AND_ANALYZE_CIDR
    assert profile["title"] == "扫描并分析 10.10.0.0/24"
    assert profile["success_criteria_json"]["goal_kind"] == PLAYBOOK_SCAN_AND_ANALYZE_CIDR


def test_match_registered_playbook_prefers_verify_asset_risks_when_asset_in_context() -> None:
    decision = match_registered_playbook(
        content="验证这台资产的风险",
        page_context={"pathname": "/assets/asset-1", "asset_id": "asset-1"},
        browser_context={},
        working_context={},
    )

    assert decision is not None
    assert decision.playbook_id == PLAYBOOK_VERIFY_ASSET_RISKS
    assert decision.auto_execute_actions[0]["action_type"] == "verify_asset_risks"
    assert decision.auto_execute_actions[0]["params"]["asset_id"] == "asset-1"


def test_match_registered_playbook_reads_asset_risks_for_analysis_request() -> None:
    decision = match_registered_playbook(
        content="看看这台机器的风险详情",
        page_context={"pathname": "/assets/asset-9", "asset_id": "asset-9"},
        browser_context={},
        working_context={},
    )

    assert decision is not None
    assert decision.playbook_id == PLAYBOOK_ANALYZE_ASSET_RISKS
    assert [item["tool_name"] for item in decision.read_tool_calls] == ["get_asset_detail", "list_asset_risks"]


def test_match_registered_playbook_prepares_auto_submit_remediation_plan() -> None:
    decision = match_registered_playbook(
        content="帮我修复这台主机",
        page_context={"pathname": "/assets/asset-9", "asset_id": "asset-9"},
        browser_context={},
        working_context={},
    )

    assert decision is not None
    assert decision.playbook_id == PLAYBOOK_START_REMEDIATION_SESSION
    assert decision.needs_confirmation is True
    assert "满足" in decision.reply_markdown
    assert decision.proposed_write_actions[0]["action_type"] == "create_or_resume_remediation_session"
    assert decision.proposed_write_actions[0]["params"] == {"asset_id": "asset-9", "submit_if_ready": True}


def test_match_registered_playbook_carries_maintenance_window_id_into_remediation_plan() -> None:
    decision = match_registered_playbook(
        content="maintenance_window_id 是 mw-e2e-20260327，请继续自动修复这台主机",
        page_context={"pathname": "/assets/asset-9", "asset_id": "asset-9"},
        browser_context={},
        working_context={},
    )

    assert decision is not None
    assert decision.playbook_id == PLAYBOOK_START_REMEDIATION_SESSION
    assert "mw-e2e-20260327" in decision.reply_markdown
    assert decision.proposed_write_actions[0]["params"] == {
        "asset_id": "asset-9",
        "submit_if_ready": True,
        "maintenance_window_id": "mw-e2e-20260327",
    }


def test_match_registered_playbook_install_runner_prefers_explicit_asset_id_and_attaches_resume_action() -> None:
    decision = match_registered_playbook(
        content="继续为资产 98daed9d-3f10-4102-a113-b678f785912b 安装 Runner，然后继续自动修复",
        page_context={"pathname": "/assets/asset-old", "asset_id": "asset-old"},
        browser_context={},
        working_context={"asset_id": "asset-old"},
    )

    assert decision is not None
    assert decision.playbook_id == PLAYBOOK_INSTALL_RUNNER
    action = decision.auto_execute_actions[0]
    assert action["action_type"] == "install_runner"
    assert action["params"]["asset_id"] == "98daed9d-3f10-4102-a113-b678f785912b"
    assert action["params"]["resume_action"]["action_type"] == "create_or_resume_remediation_session"
    assert action["params"]["resume_action"]["params"] == {
        "asset_id": "98daed9d-3f10-4102-a113-b678f785912b",
        "submit_if_ready": True,
    }


def test_match_registered_playbook_replies_quickly_for_short_smalltalk() -> None:
    decision = match_registered_playbook(
        content="你好",
        page_context={"pathname": "/"},
        browser_context={},
        working_context={},
    )

    assert decision is not None
    assert decision.playbook_id == PLAYBOOK_QUICK_SMALLTALK
    assert decision.read_tool_calls == []
    assert decision.proposed_write_actions == []
    assert decision.auto_execute_actions == []
    assert decision.stop_reason == "playbook_quick_smalltalk"


def test_match_registered_playbook_replies_quickly_for_identity_smalltalk() -> None:
    decision = match_registered_playbook(
        content="你好，介绍一下你自己",
        page_context={"pathname": "/"},
        browser_context={},
        working_context={},
    )

    assert decision is not None
    assert decision.playbook_id == PLAYBOOK_QUICK_SMALLTALK
    assert "玄武" in decision.reply_markdown


def test_match_registered_playbook_does_not_let_smalltalk_mask_business_intent() -> None:
    decision = match_registered_playbook(
        content="你好，帮我扫描并分析 10.10.0.0/24 的风险",
        page_context={"pathname": "/discovery"},
        browser_context={},
        working_context={},
    )

    assert decision is not None
    assert decision.playbook_id == PLAYBOOK_SCAN_AND_ANALYZE_CIDR
