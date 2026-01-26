import asyncio
import time

import pytest

from tollgate import (
    AgentContext,
    ApprovalOutcome,
    AsyncQueueApprover,
    ControlTower,
    Decision,
    DecisionType,
    Effect,
    InMemoryApprovalStore,
    Intent,
    TollgateApprovalDenied,
    TollgateDeferred,
    ToolRequest,
)


class MockPolicy:
    def evaluate(self, _ctx, _intent, _req):
        return Decision(decision=DecisionType.ASK, reason="verification needed")


class MockAudit:
    def emit(self, event):
        pass


@pytest.mark.asyncio
async def test_deferred_flow():
    store = InMemoryApprovalStore()
    approver = AsyncQueueApprover(store, timeout=0.1)
    tower = ControlTower(MockPolicy(), approver, MockAudit())

    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")
    req = ToolRequest("t", "a", "r", Effect.WRITE, {})

    # 1. Test Timeout / Denied
    with pytest.raises(TollgateApprovalDenied):
        await tower.execute_async(ctx, intent, req, lambda: asyncio.sleep(0))

    # 2. Test Approval flow
    class DeferredApprover:
        async def request_approval_async(self, *_args):
            return ApprovalOutcome.DEFERRED

    tower_deferred = ControlTower(MockPolicy(), DeferredApprover(), MockAudit())
    with pytest.raises(TollgateDeferred):
        await tower_deferred.execute_async(ctx, intent, req, lambda: asyncio.sleep(0))


@pytest.mark.asyncio
async def test_store_expiry():
    store = InMemoryApprovalStore()
    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")
    req = ToolRequest("t", "a", "r", Effect.WRITE, {})

    # Create a request that is already expired
    approval_id = await store.create_request(
        ctx, intent, req, "hash", "reason", time.time() - 10
    )

    outcome = await store.wait_for_decision(approval_id, timeout=0.1)
    assert outcome == ApprovalOutcome.TIMEOUT
