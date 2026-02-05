import time

import pytest

from tollgate import (
    AgentContext,
    ControlTower,
    Decision,
    DecisionType,
    Effect,
    Grant,
    InMemoryGrantStore,
    Intent,
    Outcome,
    ToolRequest,
)


class MockPolicy:
    def evaluate(self, _ctx, _intent, _req):
        return Decision(
            decision=DecisionType.ASK, reason="Needs approval", policy_version="1"
        )


class MockApprover:
    async def request_approval_async(self, *_args):
        # This should NOT be called if a grant matches
        pytest.fail("Approver should not be called when a grant matches")


class MockAudit:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


@pytest.fixture
def agent_ctx():
    return AgentContext(agent_id="agent-1", version="1.0.0", owner="user-1")


@pytest.fixture
def tool_req():
    return ToolRequest(
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        effect=Effect.READ,
        params={"id": 1},
    )


@pytest.mark.asyncio
async def test_create_and_find_grant(agent_ctx, tool_req):
    store = InMemoryGrantStore()
    # Test auto-generating ID
    grant = Grant(
        agent_id="agent-1",
        effect=Effect.READ,
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        expires_at=time.time() + 3600,
        granted_by="admin",
        created_at=time.time(),
    )
    assert grant.id is not None
    await store.create_grant(grant)

    found = await store.find_matching_grant(agent_ctx, tool_req)
    assert found is not None
    assert found.id == grant.id


@pytest.mark.asyncio
async def test_grant_usage_counter(agent_ctx, tool_req):
    store = InMemoryGrantStore()
    grant = Grant(
        agent_id="agent-1",
        effect=Effect.READ,
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        expires_at=time.time() + 3600,
        granted_by="admin",
        created_at=time.time(),
    )
    await store.create_grant(grant)

    assert await store.get_usage_count(grant.id) == 0
    await store.find_matching_grant(agent_ctx, tool_req)
    assert await store.get_usage_count(grant.id) == 1
    await store.find_matching_grant(agent_ctx, tool_req)
    assert await store.get_usage_count(grant.id) == 2


@pytest.mark.asyncio
async def test_grant_expiry(agent_ctx, tool_req):
    store = InMemoryGrantStore()
    grant = Grant(
        agent_id="agent-1",
        effect=Effect.READ,
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        expires_at=time.time() - 1,  # Expired
        granted_by="admin",
        created_at=time.time() - 3600,
    )
    await store.create_grant(grant)

    found = await store.find_matching_grant(agent_ctx, tool_req)
    assert found is None


@pytest.mark.asyncio
async def test_grant_wildcard_agent(tool_req):
    store = InMemoryGrantStore()
    grant = Grant(
        agent_id=None,  # Wildcard
        effect=Effect.READ,
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        expires_at=time.time() + 3600,
        granted_by="admin",
        created_at=time.time(),
    )
    await store.create_grant(grant)

    ctx2 = AgentContext(agent_id="any-agent", version="1", owner="o")
    found = await store.find_matching_grant(ctx2, tool_req)
    assert found is not None


@pytest.mark.asyncio
async def test_grant_wildcard_effect(agent_ctx, tool_req):
    store = InMemoryGrantStore()
    grant = Grant(
        agent_id="agent-1",
        effect=None,  # Wildcard
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        expires_at=time.time() + 3600,
        granted_by="admin",
        created_at=time.time(),
    )
    await store.create_grant(grant)

    found = await store.find_matching_grant(agent_ctx, tool_req)
    assert found is not None


@pytest.mark.asyncio
async def test_grant_tool_prefix_match(agent_ctx, tool_req):
    store = InMemoryGrantStore()
    grant = Grant(
        agent_id="agent-1",
        effect=Effect.READ,
        tool="mcp:*",  # Prefix match
        action="read",
        resource_type="data",
        expires_at=time.time() + 3600,
        granted_by="admin",
        created_at=time.time(),
    )
    await store.create_grant(grant)

    found = await store.find_matching_grant(agent_ctx, tool_req)
    assert found is not None


@pytest.mark.asyncio
async def test_grant_no_match(agent_ctx):
    store = InMemoryGrantStore()
    grant = Grant(
        agent_id="agent-1",
        effect=Effect.WRITE,  # Mismatch (READ vs WRITE)
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        expires_at=time.time() + 3600,
        granted_by="admin",
        created_at=time.time(),
    )
    await store.create_grant(grant)

    req = ToolRequest(
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        effect=Effect.READ,
        params={},
    )
    found = await store.find_matching_grant(agent_ctx, req)
    assert found is None


@pytest.mark.asyncio
async def test_revoke_grant(agent_ctx, tool_req):
    store = InMemoryGrantStore()
    grant = Grant(
        agent_id="agent-1",
        effect=Effect.READ,
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        expires_at=time.time() + 3600,
        granted_by="admin",
        created_at=time.time(),
    )
    await store.create_grant(grant)
    await store.revoke_grant(grant.id)

    found = await store.find_matching_grant(agent_ctx, tool_req)
    assert found is None


@pytest.mark.asyncio
async def test_cleanup_expired():
    store = InMemoryGrantStore()
    g1 = Grant(
        agent_id=None,
        effect=None,
        tool=None,
        action=None,
        resource_type=None,
        expires_at=time.time() - 1,
        granted_by="a",
        created_at=time.time(),
    )
    g2 = Grant(
        agent_id=None,
        effect=None,
        tool=None,
        action=None,
        resource_type=None,
        expires_at=time.time() + 10,
        granted_by="a",
        created_at=time.time(),
    )
    await store.create_grant(g1)
    await store.create_grant(g2)

    cleaned = await store.cleanup_expired()
    assert cleaned == 1
    active = await store.list_active_grants()
    assert len(active) == 1
    assert active[0].id == g2.id


@pytest.mark.asyncio
async def test_tower_uses_grant(agent_ctx, tool_req):
    store = InMemoryGrantStore()
    audit = MockAudit()
    approver = MockApprover()
    tower = ControlTower(MockPolicy(), approver, audit, grant_store=store)

    grant = Grant(
        agent_id="agent-1",
        effect=Effect.READ,
        tool="mcp:server.read",
        action="read",
        resource_type="data",
        expires_at=time.time() + 3600,
        granted_by="admin",
        created_at=time.time(),
    )
    await store.create_grant(grant)

    async def tool_fn():
        return "ok"

    intent = Intent(action="test", reason="test")
    result = await tower.execute_async(agent_ctx, intent, tool_req, tool_fn)

    assert result == "ok"
    assert len(audit.events) > 0
    event = audit.events[-1]
    assert event.grant_id == grant.id
    assert event.outcome == Outcome.EXECUTED


@pytest.mark.asyncio
async def test_grant_store_protocol_compliance():
    """Verify InMemoryGrantStore implements GrantStore protocol."""
    from tollgate import GrantStore, InMemoryGrantStore

    store = InMemoryGrantStore()

    # Protocol requires these methods exist and are callable
    assert hasattr(store, "create_grant")
    assert hasattr(store, "find_matching_grant")
    assert hasattr(store, "revoke_grant")
    assert hasattr(store, "list_active_grants")
    assert hasattr(store, "cleanup_expired")
    assert hasattr(store, "get_usage_count")

    # Verify it's recognized as implementing the protocol
    # Note: requires runtime_checkable on GrantStore
    assert isinstance(store, GrantStore)
