import pytest

from tollgate import (
    AgentContext,
    ApprovalOutcome,
    ControlTower,
    Decision,
    DecisionType,
    Effect,
    Intent,
    guard,
    wrap_tool,
)


class MockPolicy:
    def evaluate(self, _ctx, _intent, _req):
        return Decision(decision=DecisionType.ALLOW, reason="ok")


class MockApprover:
    async def request_approval_async(self, *_args):
        return ApprovalOutcome.APPROVED


class MockAudit:
    def emit(self, event):
        pass


@pytest.fixture
def tower():
    return ControlTower(MockPolicy(), MockApprover(), MockAudit())


def test_v1_wrap_tool(tower):
    def my_tool(x):
        return x * 2

    wrapped = wrap_tool(
        tower,
        my_tool,
        tool="t",
        action="a",
        resource_type="r",
        effect=Effect.READ,
    )

    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")

    assert wrapped(ctx, intent, x=5) == 10


def test_v1_guard_decorator(tower):
    @guard(tower, tool="t", action="a", resource_type="r", effect=Effect.WRITE)
    def my_tool(y):
        return y + 1

    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")

    assert my_tool(ctx, intent, y=10) == 11
