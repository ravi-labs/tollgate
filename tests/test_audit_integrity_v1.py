from tollgate import (
    AgentContext,
    ApprovalOutcome,
    ControlTower,
    DecisionType,
    Effect,
    Intent,
    ToolRequest,
)


class MockPolicy:
    def evaluate(self, _ctx, _intent, _req):
        from tollgate import Decision

        return Decision(decision=DecisionType.ALLOW, reason="ok")


class MockApprover:
    async def request_approval_async(self, *_args):
        return ApprovalOutcome.APPROVED


class MockAudit:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def test_audit_redaction_and_hash():
    def redact_secrets(params):
        new_params = params.copy()
        if "password" in new_params:
            new_params["password"] = "[REDACTED]"
        return new_params

    audit = MockAudit()
    tower = ControlTower(MockPolicy(), MockApprover(), audit, redact_fn=redact_secrets)

    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")
    req = ToolRequest("t", "a", "r", Effect.WRITE, {"password": "secret_123", "id": 1})

    tower.execute(ctx, intent, req, lambda: "done")

    assert len(audit.events) > 0
    event = audit.events[-1]

    # 1. Verify Redaction
    assert event.tool_request.params["password"] == "[REDACTED]"
    assert event.tool_request.params["id"] == 1

    # 2. Verify Request Hash exists and is structured
    assert event.request_hash is not None
    assert len(event.request_hash) == 64  # SHA-256
