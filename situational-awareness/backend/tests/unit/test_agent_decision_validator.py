from app.services.agent.decision_validator import validate_agent_write_decisions


def test_decision_validator_downgrades_auto_action_outside_current_asset_scope() -> None:
    result = validate_agent_write_decisions(
        auto_actions=[
            {
                "action_type": "install_runner",
                "title": "安装 Runner",
                "reason": "用户要求安装",
                "params": {"asset_id": "asset-2"},
            }
        ],
        proposed_actions=[],
        working_context={"asset_id": "asset-1", "primary_target": {"asset_id": "asset-1"}},
        page_context={"asset_id": "asset-1"},
        browser_context={"asset_id": "asset-1"},
        user_role="admin",
    )

    assert result.auto_actions == []
    assert result.downgraded is True
    assert result.proposed_actions[0]["validation"]["requires_human_confirmation"] is True
    assert result.issues[0].code == "asset_scope_mismatch"


def test_decision_validator_keeps_low_risk_auto_action_in_scope() -> None:
    result = validate_agent_write_decisions(
        auto_actions=[
            {
                "action_type": "verify_asset_risks",
                "title": "验证风险",
                "reason": "用户明确要求",
                "params": {"asset_id": "asset-1"},
            }
        ],
        proposed_actions=[],
        working_context={"asset_id": "asset-1"},
        page_context={"asset_id": "asset-1"},
        browser_context={"asset_id": "asset-1"},
        user_role="admin",
    )

    assert len(result.auto_actions) == 1
    assert result.proposed_actions == []
    assert result.issues == []
