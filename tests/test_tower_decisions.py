import pytest

from tollgate import (
    AgentContext,
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
            decision=self.decision_type, reason=f"Mock {self.decision_type}"
        )


class MockApprover:
    def __init__(self, approved: bool):
        self.approved = approved

    def request_approval(self, _agent_ctx, _intent, _tool_request, _reason):
        return self.approved


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
    )


def test_tower_allow(agent_ctx, intent, tool_req):
    audit = MockAudit()
    tower = ControlTower(MockPolicy(DecisionType.ALLOW), MockApprover(True), audit)

    counter = {"val": 0}

    def tool_fn(x):
        counter["val"] += x
        return "ok"

    result = tower.execute(agent_ctx, intent, tool_req, tool_fn)

    assert result == "ok"
    assert counter["val"] == 1
    assert audit.events[-1].outcome == Outcome.EXECUTED


def test_tower_deny(agent_ctx, intent, tool_req):
    audit = MockAudit()
    tower = ControlTower(MockPolicy(DecisionType.DENY), MockApprover(True), audit)

    counter = {"val": 0}

    def tool_fn(x):
        counter["val"] += x

    with pytest.raises(TollgateDenied):
        tower.execute(agent_ctx, intent, tool_req, tool_fn)

    assert counter["val"] == 0
    assert audit.events[-1].outcome == Outcome.BLOCKED


def test_tower_ask_approved(agent_ctx, intent, tool_req):
    audit = MockAudit()
    tower = ControlTower(MockPolicy(DecisionType.ASK), MockApprover(True), audit)

    counter = {"val": 0}

    def tool_fn(x):
        counter["val"] += x
        return "ok"

    result = tower.execute(agent_ctx, intent, tool_req, tool_fn)

    assert result == "ok"
    assert counter["val"] == 1
    assert audit.events[-1].outcome == Outcome.EXECUTED


def test_tower_ask_denied(agent_ctx, intent, tool_req):
    audit = MockAudit()
    tower = ControlTower(MockPolicy(DecisionType.ASK), MockApprover(False), audit)

    counter = {"val": 0}

    def tool_fn(x):
        counter["val"] += x

    with pytest.raises(TollgateApprovalDenied):
        tower.execute(agent_ctx, intent, tool_req, tool_fn)

    assert counter["val"] == 0
    assert audit.events[-1].outcome == Outcome.APPROVAL_DENIED
