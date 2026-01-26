import asyncio

import pytest

from tollgate import (
    AgentContext,
    ApprovalOutcome,
    ControlTower,
    DecisionType,
    Effect,
    Intent,
    Outcome,
    TollgateApprovalDenied,
    ToolRequest,
)


class MockPolicy:
    def evaluate(self, _ctx, _intent, _req):
        from tollgate import Decision

        return Decision(decision=DecisionType.ASK, reason="Needs approval")


class MockApprover:
    async def request_approval_async(self, _ctx, _intent, _req, _hash, _reason):
        return ApprovalOutcome.APPROVED


class MockAudit:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


@pytest.mark.asyncio
async def test_audit_redaction():
    audit = MockAudit()

    # Redact any key named 'secret'
    def redact(params):
        return {k: ("***" if k == "secret" else v) for k, v in params.items()}

    tower = ControlTower(MockPolicy(), MockApprover(), audit, redact_fn=redact)

    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")
    req = ToolRequest(
        "t", "a", "res", Effect.WRITE, {"secret": "12345", "public": "hi"}
    )

    await tower.execute_async(ctx, intent, req, lambda: asyncio.sleep(0))

    # Check that the audit event contains redacted params
    event = audit.events[-1]
    assert event.tool_request.params["secret"] == "***"
    assert event.tool_request.params["public"] == "hi"


@pytest.mark.asyncio
async def test_approver_timeout_behavior():
    class TimeoutApprover:
        async def request_approval_async(self, *_args):
            return ApprovalOutcome.TIMEOUT

    audit = MockAudit()
    tower = ControlTower(MockPolicy(), TimeoutApprover(), audit)

    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")
    req = ToolRequest("t", "a", "res", Effect.WRITE, {})

    with pytest.raises(TollgateApprovalDenied, match="timeout"):
        await tower.execute_async(ctx, intent, req, lambda: None)

    assert any(e.outcome == Outcome.TIMEOUT for e in audit.events)
