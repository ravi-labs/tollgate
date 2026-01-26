from tollgate import (
    AgentContext,
    DecisionType,
    Effect,
    Intent,
    ToolRequest,
    YamlPolicyEvaluator,
)


def test_policy_trusted_requirement(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("""
rules:
  - id: allow_read
    effect: read
    decision: ALLOW
""")

    evaluator = YamlPolicyEvaluator(policy)
    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    # Untrusted request (no manifest_version) => should be ASK, not ALLOW
    req_untrusted = ToolRequest(
        tool="t", action="a", resource_type="r", effect=Effect.READ, params={}
    )
    res = evaluator.evaluate(ctx, intent, req_untrusted)
    assert res.decision == DecisionType.ASK
    assert "trusted" in res.reason

    # Trusted request => ALLOW
    req_trusted = ToolRequest(
        tool="t",
        action="a",
        resource_type="r",
        effect=Effect.READ,
        params={},
        manifest_version="1.0.0",
    )
    res = evaluator.evaluate(ctx, intent, req_trusted)
    assert res.decision == DecisionType.ALLOW


def test_policy_unknown_effect_default(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []")

    evaluator = YamlPolicyEvaluator(policy, default_if_unknown=DecisionType.DENY)
    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    req_unknown = ToolRequest(
        tool="t", action="a", resource_type="r", effect=Effect.UNKNOWN, params={}
    )
    res = evaluator.evaluate(ctx, intent, req_unknown)
    assert res.decision == DecisionType.DENY


def test_policy_when_condition_match(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("""
rules:
  - id: deny_vip
    decision: DENY
    when:
      is_vip: true
""")
    evaluator = YamlPolicyEvaluator(policy)
    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    req_vip = ToolRequest(
        tool="t",
        action="a",
        resource_type="r",
        effect=Effect.WRITE,
        params={},
        metadata={"is_vip": True},
    )
    res = evaluator.evaluate(ctx, intent, req_vip)
    assert res.decision == DecisionType.DENY
