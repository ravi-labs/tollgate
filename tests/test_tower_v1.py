import pytest

from tollgate import (
    AgentContext,
    ApprovalOutcome,
    ControlTower,
    Decision,
    DecisionType,
    Effect,
    Intent,
    Outcome,
    TollgateApprovalDenied,
    TollgateDenied,
    ToolRequest,
)


class MockPolicy:
    def __init__(self, decision_type: DecisionType):
        self.decision_type = decision_type

    def evaluate(self, _agent_ctx, _intent, _tool_request):
        return Decision(
            decision=self.decision_type,
            reason=f"Mock {self.decision_type}",
            policy_version="1.0.0",
        )


class MockApprover:
    def __init__(self, outcome: ApprovalOutcome):
        self.outcome = outcome

    async def request_approval_async(self, _ctx, _intent, _req, _hash, _reason):
        return self.outcome


class MockAudit:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


@pytest.fixture
def agent_ctx():
    return AgentContext(agent_id="test", version="1", owner="user")


@pytest.fixture
def intent():
    return Intent(action="test_action", reason="test")


@pytest.fixture
def tool_req():
    return ToolRequest(
        tool="mock",
        action="run",
        resource_type="none",
        effect=Effect.READ,
        params={"x": 1},
        manifest_version="1.0.0",
    )


@pytest.mark.asyncio
async def test_tower_v1_allow(agent_ctx, intent, tool_req):
    audit = MockAudit()
    approver = MockApprover(ApprovalOutcome.APPROVED)
    tower = ControlTower(MockPolicy(DecisionType.ALLOW), approver, audit)

    counter = {"val": 0}

    async def tool_fn():
        counter["val"] += 1
        return "ok"

    result = await tower.execute_async(agent_ctx, intent, tool_req, tool_fn)

    assert result == "ok"
    assert counter["val"] == 1
    assert any(e.outcome == Outcome.EXECUTED for e in audit.events)


@pytest.mark.asyncio
async def test_tower_v1_deny(agent_ctx, intent, tool_req):
    audit = MockAudit()
    approver = MockApprover(ApprovalOutcome.APPROVED)
    tower = ControlTower(MockPolicy(DecisionType.DENY), approver, audit)

    async def tool_fn():
        return "ok"

    with pytest.raises(TollgateDenied):
        await tower.execute_async(agent_ctx, intent, tool_req, tool_fn)

    assert any(e.outcome == Outcome.BLOCKED for e in audit.events)


@pytest.mark.asyncio
async def test_tower_v1_ask_approved(agent_ctx, intent, tool_req):
    audit = MockAudit()
    approver = MockApprover(ApprovalOutcome.APPROVED)
    tower = ControlTower(MockPolicy(DecisionType.ASK), approver, audit)

    async def tool_fn():
        return "ok"

    result = await tower.execute_async(agent_ctx, intent, tool_req, tool_fn)

    assert result == "ok"
    assert any(e.outcome == Outcome.EXECUTED for e in audit.events)


@pytest.mark.asyncio
async def test_tower_v1_ask_denied(agent_ctx, intent, tool_req):
    audit = MockAudit()
    approver = MockApprover(ApprovalOutcome.DENIED)
    tower = ControlTower(MockPolicy(DecisionType.ASK), approver, audit)

    async def tool_fn():
        return "ok"

    with pytest.raises(TollgateApprovalDenied):
        await tower.execute_async(agent_ctx, intent, tool_req, tool_fn)

    assert any(e.outcome == Outcome.APPROVAL_DENIED for e in audit.events)


def test_tower_v1_sync_wrapper(agent_ctx, intent, tool_req):
    audit = MockAudit()
    approver = MockApprover(ApprovalOutcome.APPROVED)
    tower = ControlTower(MockPolicy(DecisionType.ALLOW), approver, audit)

    def tool_fn():
        return "ok"

    result = tower.execute(agent_ctx, intent, tool_req, tool_fn)
    assert result == "ok"
