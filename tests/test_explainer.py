"""Tests for DecisionExplainer."""

import tempfile
from pathlib import Path

import pytest

from tollgate import (
    AgentContext,
    DecisionExplainer,
    DecisionType,
    Effect,
    ExplanationResult,
    Intent,
    ToolRequest,
    YamlPolicyEvaluator,
)


@pytest.fixture
def policy_file():
    """Create a temporary policy file."""
    content = """
version: "test-v1"
rules:
  - id: allow_read
    decision: ALLOW
    effect: read
    reason: "Read operations are allowed"

  - id: deny_delete
    decision: DENY
    effect: delete
    reason: "Delete operations are blocked"

  - id: ask_write
    decision: ASK
    effect: write
    reason: "Write operations need approval"

  - id: agent_specific
    decision: ALLOW
    tool: special:tool
    agent:
      agent_id: privileged-agent
    reason: "Privileged agent can use special tool"

  - id: catch_all
    decision: DENY
    reason: "Default deny"
"""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(content)
        f.flush()
        yield Path(f.name)


@pytest.fixture
def explainer(policy_file):
    """Create a DecisionExplainer instance."""
    evaluator = YamlPolicyEvaluator(policy_file)
    return DecisionExplainer(evaluator)


def test_explain_allow_decision(explainer):
    """Test explanation for an ALLOW decision."""
    ctx = AgentContext(agent_id="test", version="1.0", owner="user")
    intent = Intent(action="fetch", reason="test")
    req = ToolRequest(
        tool="api:fetch",
        action="get",
        resource_type="url",
        effect=Effect.READ,
        params={},
        manifest_version="1.0.0",
    )

    result = explainer.explain(ctx, intent, req)

    assert isinstance(result, ExplanationResult)
    assert result.decision.decision == DecisionType.ALLOW
    assert result.matched_rule_index == 0
    assert result.matched_rule is not None
    assert result.matched_rule.rule_id == "allow_read"
    assert result.rules_checked == 1


def test_explain_deny_decision(explainer):
    """Test explanation for a DENY decision."""
    ctx = AgentContext(agent_id="test", version="1.0", owner="user")
    intent = Intent(action="remove", reason="test")
    req = ToolRequest(
        tool="api:remove",
        action="delete",
        resource_type="file",
        effect=Effect.DELETE,
        params={},
        manifest_version="1.0.0",
    )

    result = explainer.explain(ctx, intent, req)

    assert result.decision.decision == DecisionType.DENY
    assert result.matched_rule.rule_id == "deny_delete"
    assert "Delete operations" in result.decision.reason


def test_explain_ask_decision(explainer):
    """Test explanation for an ASK decision."""
    ctx = AgentContext(agent_id="test", version="1.0", owner="user")
    intent = Intent(action="update", reason="test")
    req = ToolRequest(
        tool="api:update",
        action="put",
        resource_type="record",
        effect=Effect.WRITE,
        params={},
        manifest_version="1.0.0",
    )

    result = explainer.explain(ctx, intent, req)

    assert result.decision.decision == DecisionType.ASK
    assert result.matched_rule.rule_id == "ask_write"


def test_explain_no_manifest_version(explainer):
    """Test that ALLOW without manifest_version becomes ASK."""
    ctx = AgentContext(agent_id="test", version="1.0", owner="user")
    intent = Intent(action="fetch", reason="test")
    req = ToolRequest(
        tool="api:fetch",
        action="get",
        resource_type="url",
        effect=Effect.READ,
        params={},
        manifest_version=None,  # No manifest version
    )

    result = explainer.explain(ctx, intent, req)

    # Should be ASK because no manifest_version
    assert result.decision.decision == DecisionType.ASK
    assert "trusted tool metadata" in result.decision.reason


def test_explain_unknown_effect(explainer):
    """Test explanation for unknown effect."""
    ctx = AgentContext(agent_id="test", version="1.0", owner="user")
    intent = Intent(action="test", reason="test")
    req = ToolRequest(
        tool="test:tool",
        action="test",
        resource_type="test",
        effect=Effect.UNKNOWN,
        params={},
    )

    result = explainer.explain(ctx, intent, req)

    assert result.decision.decision == DecisionType.DENY
    assert "Unknown tool effect" in result.decision.reason
    assert result.matched_rule_index is None
    assert len(result.rule_evaluations) == 0


def test_explain_agent_specific_rule(explainer):
    """Test explanation with agent-specific matching."""
    # Non-privileged agent
    ctx1 = AgentContext(agent_id="normal-agent", version="1.0", owner="user")
    intent = Intent(action="use", reason="test")
    req = ToolRequest(
        tool="special:tool",
        action="invoke",
        resource_type="special",
        effect=Effect.NOTIFY,
        params={},
        manifest_version="1.0.0",
    )

    result1 = explainer.explain(ctx1, intent, req)

    # Should fall through to catch_all deny
    assert result1.decision.decision == DecisionType.DENY
    assert result1.matched_rule.rule_id == "catch_all"

    # Privileged agent
    ctx2 = AgentContext(agent_id="privileged-agent", version="1.0", owner="user")
    result2 = explainer.explain(ctx2, intent, req)

    assert result2.decision.decision == DecisionType.ALLOW
    assert result2.matched_rule.rule_id == "agent_specific"


def test_rule_match_result_details(explainer):
    """Test that rule match results contain proper details."""
    ctx = AgentContext(agent_id="test", version="1.0", owner="user")
    intent = Intent(action="fetch", reason="test")
    req = ToolRequest(
        tool="api:fetch",
        action="get",
        resource_type="url",
        effect=Effect.READ,
        params={},
        manifest_version="1.0.0",
    )

    result = explainer.explain(ctx, intent, req)

    # Check the matched rule has details
    matched = result.matched_rule
    assert matched is not None
    assert matched.matched is True
    assert len(matched.match_details) > 0
    assert "effect=read" in matched.match_details


def test_explain_many(explainer):
    """Test explaining multiple scenarios."""
    scenarios = [
        (
            AgentContext(agent_id="test", version="1.0", owner="user"),
            Intent(action="fetch", reason="test"),
            ToolRequest(
                tool="api:fetch",
                action="get",
                resource_type="url",
                effect=Effect.READ,
                params={},
                manifest_version="1.0.0",
            ),
        ),
        (
            AgentContext(agent_id="test", version="1.0", owner="user"),
            Intent(action="remove", reason="test"),
            ToolRequest(
                tool="api:remove",
                action="delete",
                resource_type="file",
                effect=Effect.DELETE,
                params={},
                manifest_version="1.0.0",
            ),
        ),
    ]

    results = explainer.explain_many(scenarios)

    assert len(results) == 2
    assert results[0].decision.decision == DecisionType.ALLOW
    assert results[1].decision.decision == DecisionType.DENY


def test_summary_output(explainer):
    """Test summary string generation."""
    ctx = AgentContext(agent_id="test", version="1.0", owner="user")
    intent = Intent(action="fetch", reason="test")
    req = ToolRequest(
        tool="api:fetch",
        action="get",
        resource_type="url",
        effect=Effect.READ,
        params={},
        manifest_version="1.0.0",
    )

    result = explainer.explain(ctx, intent, req)
    summary = result.summary()

    assert "Decision: ALLOW" in summary
    assert "Matched Rule: allow_read" in summary
    assert "Rules Checked: 1" in summary


def test_detailed_report_output(explainer):
    """Test detailed report generation."""
    ctx = AgentContext(
        agent_id="test",
        version="1.0",
        owner="user",
        metadata={"org_id": "org-123"},
    )
    intent = Intent(action="fetch", reason="test")
    req = ToolRequest(
        tool="api:fetch",
        action="get",
        resource_type="url",
        effect=Effect.READ,
        params={},
        manifest_version="1.0.0",
    )

    result = explainer.explain(ctx, intent, req)
    report = result.detailed_report()

    # Check report contains key sections
    assert "DECISION EXPLANATION" in report
    assert "REQUEST CONTEXT" in report
    assert "POLICY EVALUATION" in report
    assert "FINAL DECISION" in report
    assert "Agent ID: test" in report
    assert "Org ID: org-123" in report
