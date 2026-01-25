from pathlib import Path

import pytest

from tollgate import (
    AgentContext,
    DecisionType,
    Effect,
    Intent,
    ToolRequest,
    YamlPolicyEvaluator,
)


@pytest.fixture
def policy_file(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
rules:
  - id: test_gt
    decision: ALLOW
    when:
      val: {">": 10}
  - id: test_ne
    decision: ALLOW
    when:
      status: {"!=": "closed"}
  - id: test_null
    decision: DENY
    when:
      missing: {">": 10}
""")
    return p


def test_check_condition_gt(policy_file):
    evaluator = YamlPolicyEvaluator(policy_file)
    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    # GT matches
    req1 = ToolRequest(
        tool="t",
        action="a",
        resource_type="r",
        effect=Effect.READ,
        params={},
        metadata={"val": 15},
    )
    assert evaluator.evaluate(ctx, intent, req1).decision == DecisionType.ALLOW

    # GT fails
    req2 = ToolRequest(
        tool="t",
        action="a",
        resource_type="r",
        effect=Effect.READ,
        params={},
        metadata={"val": 5, "status": "closed"},
    )
    assert evaluator.evaluate(ctx, intent, req2).decision == DecisionType.DENY


def test_check_condition_ne(policy_file):
    evaluator = YamlPolicyEvaluator(policy_file)
    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    # NE matches
    req1 = ToolRequest(
        tool="t",
        action="a",
        resource_type="r",
        effect=Effect.READ,
        params={},
        metadata={"status": "open"},
    )
    assert evaluator.evaluate(ctx, intent, req1).decision == DecisionType.ALLOW

    # NE fails
    req2 = ToolRequest(
        tool="t",
        action="a",
        resource_type="r",
        effect=Effect.READ,
        params={},
        metadata={"status": "closed"},
    )
    assert evaluator.evaluate(ctx, intent, req2).decision == DecisionType.DENY


def test_check_condition_null_safe(policy_file):
    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    # Wait, if it doesn't match it hits default DENY anyway.
    # Let's make it more explicit.
    p2 = Path(policy_file).parent / "policy2.yaml"
    p2.write_text("""
rules:
  - id: deny_if_gt
    decision: DENY
    when:
      val: {">": 10}
  - id: allow_fallback
    decision: ALLOW
""")
    evaluator2 = YamlPolicyEvaluator(p2)
    req2 = ToolRequest(
        tool="t",
        action="a",
        resource_type="r",
        effect=Effect.READ,
        params={},
        metadata={},
    )
    assert evaluator2.evaluate(ctx, intent, req2).decision == DecisionType.ALLOW
