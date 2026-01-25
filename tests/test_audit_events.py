import json

from tollgate import (
    AgentContext,
    CliApprover,
    ControlTower,
    Effect,
    Intent,
    JsonlAuditSink,
    ToolRequest,
    YamlPolicyEvaluator,
)


def test_audit_jsonl_output(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text("""
rules:
  - id: allow_all
    decision: ALLOW
""")

    sink = JsonlAuditSink(log_file)
    tower = ControlTower(YamlPolicyEvaluator(policy_file), CliApprover(), sink)

    ctx = AgentContext(agent_id="test", version="1", owner="user")
    intent = Intent(action="test", reason="test")
    req = ToolRequest(
        tool="mock", action="run", resource_type="none", effect=Effect.READ, params={}
    )

    tower.execute(ctx, intent, req, lambda: "done")

    assert log_file.exists()
    with log_file.open() as f:
        line = f.readline()
        event = json.loads(line)
        assert event["correlation_id"] is not None
        assert event["outcome"] == "executed"
        assert event["agent"]["agent_id"] == "test"
