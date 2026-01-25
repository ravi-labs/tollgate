import pytest

from tollgate import (
    AgentContext,
    ControlTower,
    Decision,
    DecisionType,
    Effect,
    Intent,
    guard,
    wrap_tool,
)


class MockApprover:
    def request_approval(self, _ctx, _intent, _req, _reason):
        return True


class MockAudit:
    def emit(self, _event):
        pass


@pytest.fixture
def tower():
    class SimplePolicy:
        def evaluate(self, _ctx, _intent, _req):
            return Decision(decision=DecisionType.ALLOW, reason="ok")

    return ControlTower(SimplePolicy(), MockApprover(), MockAudit())


def test_wrap_tool(tower):
    def my_tool(x, y):
        return x + y

    wrapped = wrap_tool(
        tower, my_tool, tool="t", action="a", resource_type="r", effect=Effect.READ
    )

    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    result = wrapped(ctx, intent, x=1, y=2)
    assert result == 3


def test_guard_decorator(tower):
    @guard(tower, tool="t", action="a", resource_type="r", effect=Effect.WRITE)
    def my_guarded_tool(z):
        return z * 2

    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    result = my_guarded_tool(ctx, intent, z=5)
    assert result == 10


def test_wrap_tool_with_metadata(tower):
    def my_tool_meta():
        return "ok"

    wrapped = wrap_tool(
        tower, my_tool_meta, tool="t", action="a", resource_type="r", effect=Effect.READ
    )

    ctx = AgentContext(agent_id="a", version="1", owner="o")
    intent = Intent(action="i", reason="r")

    class MetaPolicy:
        def evaluate(self, _ctx, _intent, req):
            if req.metadata.get("secret") == "xyz":
                return Decision(decision=DecisionType.ALLOW, reason="allowed")
            return Decision(decision=DecisionType.DENY, reason="denied")

    tower.policy = MetaPolicy()

    # Should be allowed with metadata
    assert wrapped(ctx, intent, metadata={"secret": "xyz"}) == "ok"

    # Should be denied without metadata
    from tollgate import TollgateDenied

    with pytest.raises(TollgateDenied):
        wrapped(ctx, intent)
