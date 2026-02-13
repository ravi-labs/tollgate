"""Tests for organization/tenant support."""

import time

import pytest

from tollgate import (
    AgentContext,
    Effect,
    Grant,
    InMemoryGrantStore,
    InMemoryRateLimiter,
    ToolRequest,
)

# ========== AgentContext org_id Tests ==========


class TestAgentContextOrgId:
    def test_org_id_property_returns_metadata_value(self):
        ctx = AgentContext(
            agent_id="agent-1",
            version="1.0",
            owner="user",
            metadata={"org_id": "org-123"},
        )
        assert ctx.org_id == "org-123"

    def test_org_id_none_when_not_set(self):
        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="user")
        assert ctx.org_id is None

    def test_org_id_none_when_metadata_empty(self):
        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="user", metadata={})
        assert ctx.org_id is None

    def test_with_org_factory_sets_org_id(self):
        ctx = AgentContext.with_org(
            agent_id="agent-1",
            version="1.0",
            owner="user",
            org_id="org-123",
        )
        assert ctx.org_id == "org-123"
        assert ctx.agent_id == "agent-1"
        assert ctx.version == "1.0"
        assert ctx.owner == "user"

    def test_with_org_preserves_other_metadata(self):
        ctx = AgentContext.with_org(
            agent_id="agent-1",
            version="1.0",
            owner="user",
            org_id="org-123",
            metadata={"custom_key": "custom_value"},
        )
        assert ctx.org_id == "org-123"
        assert ctx.metadata["custom_key"] == "custom_value"

    def test_with_org_supports_delegated_by(self):
        ctx = AgentContext.with_org(
            agent_id="agent-1",
            version="1.0",
            owner="user",
            org_id="org-123",
            delegated_by=("orchestrator",),
        )
        assert ctx.org_id == "org-123"
        assert ctx.is_delegated
        assert ctx.delegated_by == ("orchestrator",)

    def test_to_dict_includes_org_id_in_metadata(self):
        ctx = AgentContext.with_org(
            agent_id="agent-1",
            version="1.0",
            owner="user",
            org_id="org-123",
        )
        d = ctx.to_dict()
        assert d["metadata"]["org_id"] == "org-123"


# ========== Grant org_id Tests ==========


class TestGrantOrgId:
    @pytest.mark.asyncio
    async def test_grant_with_org_id_matches_same_org_agent(self):
        store = InMemoryGrantStore()

        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-123",
        )
        await store.create_grant(grant)

        ctx = AgentContext.with_org(
            agent_id="agent-1",
            version="1.0",
            owner="user",
            org_id="org-123",
        )
        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.READ,
            params={},
        )

        found = await store.find_matching_grant(ctx, req)
        assert found is not None
        assert found.id == grant.id

    @pytest.mark.asyncio
    async def test_grant_with_org_id_does_not_match_different_org_agent(self):
        store = InMemoryGrantStore()

        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-123",
        )
        await store.create_grant(grant)

        ctx = AgentContext.with_org(
            agent_id="agent-1",
            version="1.0",
            owner="user",
            org_id="org-456",  # Different org
        )
        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.READ,
            params={},
        )

        found = await store.find_matching_grant(ctx, req)
        assert found is None

    @pytest.mark.asyncio
    async def test_grant_without_org_id_matches_any_org(self):
        store = InMemoryGrantStore()

        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id=None,  # Global grant
        )
        await store.create_grant(grant)

        # Agent with org_id
        ctx1 = AgentContext.with_org(
            agent_id="agent-1",
            version="1.0",
            owner="user",
            org_id="org-123",
        )
        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.READ,
            params={},
        )

        found = await store.find_matching_grant(ctx1, req)
        assert found is not None

        # Agent without org_id
        ctx2 = AgentContext(agent_id="agent-1", version="1.0", owner="user")
        found = await store.find_matching_grant(ctx2, req)
        assert found is not None

    @pytest.mark.asyncio
    async def test_list_active_grants_filtered_by_org(self):
        store = InMemoryGrantStore()

        g1 = Grant(
            agent_id=None,
            effect=None,
            tool=None,
            action=None,
            resource_type=None,
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-1",
        )
        g2 = Grant(
            agent_id=None,
            effect=None,
            tool=None,
            action=None,
            resource_type=None,
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-2",
        )
        g3 = Grant(
            agent_id=None,
            effect=None,
            tool=None,
            action=None,
            resource_type=None,
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id=None,  # Global
        )
        await store.create_grant(g1)
        await store.create_grant(g2)
        await store.create_grant(g3)

        # Filter by org_id
        org1_grants = await store.list_active_grants(org_id="org-1")
        assert len(org1_grants) == 1
        assert org1_grants[0].org_id == "org-1"

        org2_grants = await store.list_active_grants(org_id="org-2")
        assert len(org2_grants) == 1
        assert org2_grants[0].org_id == "org-2"

        # All grants
        all_grants = await store.list_active_grants()
        assert len(all_grants) == 3

    @pytest.mark.asyncio
    async def test_list_active_grants_filtered_by_agent_and_org(self):
        store = InMemoryGrantStore()

        g1 = Grant(
            agent_id="agent-1",
            effect=None,
            tool=None,
            action=None,
            resource_type=None,
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-1",
        )
        g2 = Grant(
            agent_id="agent-2",
            effect=None,
            tool=None,
            action=None,
            resource_type=None,
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-1",
        )
        await store.create_grant(g1)
        await store.create_grant(g2)

        grants = await store.list_active_grants(agent_id="agent-1", org_id="org-1")
        assert len(grants) == 1
        assert grants[0].agent_id == "agent-1"

    def test_grant_to_dict_includes_org_id(self):
        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-123",
        )
        d = grant.to_dict()
        assert d["org_id"] == "org-123"


# ========== Rate Limiter org_id Tests ==========


class TestRateLimiterOrgId:
    @pytest.mark.asyncio
    async def test_rate_limiter_org_scoped_rule_applies_to_matching_org(self):
        rules = [
            {
                "org_id": "org-123",
                "tool": "*",
                "max_calls": 2,
                "window_seconds": 60,
            }
        ]
        limiter = InMemoryRateLimiter(rules)

        ctx = AgentContext.with_org(
            agent_id="agent-1", version="1.0", owner="user", org_id="org-123"
        )
        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.READ,
            params={},
        )

        # First two calls allowed
        allowed, _, _ = await limiter.check_rate_limit(ctx, req)
        assert allowed
        allowed, _, _ = await limiter.check_rate_limit(ctx, req)
        assert allowed

        # Third call blocked
        allowed, reason, _ = await limiter.check_rate_limit(ctx, req)
        assert not allowed
        assert "Rate limit" in reason

    @pytest.mark.asyncio
    async def test_rate_limiter_org_scoped_rule_does_not_apply_to_different_org(self):
        rules = [
            {
                "org_id": "org-123",
                "tool": "*",
                "max_calls": 1,
                "window_seconds": 60,
            }
        ]
        limiter = InMemoryRateLimiter(rules)

        # Exhaust limit for org-123
        ctx1 = AgentContext.with_org(
            agent_id="agent-1", version="1.0", owner="user", org_id="org-123"
        )
        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.READ,
            params={},
        )
        await limiter.check_rate_limit(ctx1, req)

        # Different org should not be limited (rule doesn't match)
        ctx2 = AgentContext.with_org(
            agent_id="agent-2", version="1.0", owner="user", org_id="org-456"
        )
        allowed, _, _ = await limiter.check_rate_limit(ctx2, req)
        assert allowed  # Rule doesn't apply to different org

    @pytest.mark.asyncio
    async def test_rate_limiter_wildcard_org_applies_to_all(self):
        rules = [
            {
                "org_id": "*",
                "tool": "*",
                "max_calls": 2,
                "window_seconds": 60,
            }
        ]
        limiter = InMemoryRateLimiter(rules)

        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.READ,
            params={},
        )

        # Different orgs share the same bucket since org_id="*" in rule
        ctx1 = AgentContext.with_org(
            agent_id="agent-1", version="1.0", owner="user", org_id="org-123"
        )
        ctx2 = AgentContext.with_org(
            agent_id="agent-1", version="1.0", owner="user", org_id="org-456"
        )

        # Each agent has its own bucket (based on agent_id)
        allowed, _, _ = await limiter.check_rate_limit(ctx1, req)
        assert allowed
        allowed, _, _ = await limiter.check_rate_limit(ctx1, req)
        assert allowed
        # ctx1 is now at limit

        # ctx2 has same agent_id but different org, gets own bucket
        allowed, _, _ = await limiter.check_rate_limit(ctx2, req)
        assert allowed

    @pytest.mark.asyncio
    async def test_rate_limiter_separate_buckets_per_org(self):
        # Rule that applies to all orgs but uses org in bucket key
        rules = [
            {
                "org_id": "*",
                "agent_id": "*",
                "tool": "*",
                "max_calls": 1,
                "window_seconds": 60,
            }
        ]
        limiter = InMemoryRateLimiter(rules)

        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.READ,
            params={},
        )

        ctx1 = AgentContext.with_org(
            agent_id="agent-1", version="1.0", owner="user", org_id="org-1"
        )
        ctx2 = AgentContext.with_org(
            agent_id="agent-1", version="1.0", owner="user", org_id="org-2"
        )

        # Each org+agent combo gets its own bucket
        allowed, _, _ = await limiter.check_rate_limit(ctx1, req)
        assert allowed

        allowed, _, _ = await limiter.check_rate_limit(ctx2, req)
        assert allowed  # Different org = different bucket
