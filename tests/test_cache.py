"""Tests for grant caching layer."""

import asyncio
import time
from unittest.mock import AsyncMock

import pytest

from tollgate import AgentContext, Effect, Grant, ToolRequest
from tollgate.cache import CachedGrantStore, CacheEntry, GrantCache


@pytest.fixture
def agent_ctx():
    """Create a test agent context."""
    return AgentContext(
        agent_id="test-agent",
        version="1.0",
        owner="test-owner",
    )


@pytest.fixture
def tool_request():
    """Create a test tool request."""
    return ToolRequest(
        tool="api:fetch",
        action="get",
        resource_type="url",
        effect=Effect.READ,
        params={},
    )


@pytest.fixture
def sample_grant():
    """Create a sample grant."""
    return Grant(
        id="grant-123",
        agent_id="test-agent",
        tool="api:fetch",
        action="get",
        effect=Effect.READ,
        resource_type="url",
        expires_at=time.time() + 3600,
        granted_by="test-user",
        created_at=time.time(),
    )


@pytest.fixture
def cache():
    """Create a GrantCache instance."""
    return GrantCache(max_size=10, ttl_seconds=60)


class TestGrantCache:
    """Tests for GrantCache."""

    @pytest.mark.asyncio
    async def test_cache_miss_returns_sentinel(self, cache, agent_ctx, tool_request):
        """Test that cache miss returns CacheEntry sentinel."""
        result = await cache.get(agent_ctx, tool_request)
        assert result is CacheEntry

    @pytest.mark.asyncio
    async def test_cache_hit_returns_grant(
        self, cache, agent_ctx, tool_request, sample_grant
    ):
        """Test that cache hit returns the grant."""
        await cache.set(agent_ctx, tool_request, sample_grant)
        result = await cache.get(agent_ctx, tool_request)

        assert result == sample_grant

    @pytest.mark.asyncio
    async def test_cache_stores_none(self, cache, agent_ctx, tool_request):
        """Test that cache can store None (no grant found)."""
        await cache.set(agent_ctx, tool_request, None)
        result = await cache.get(agent_ctx, tool_request)

        assert result is None
        assert result is not CacheEntry  # None is valid, not a miss

    @pytest.mark.asyncio
    async def test_different_agents_different_keys(
        self, cache, tool_request, sample_grant
    ):
        """Test that different agents have different cache keys."""
        ctx1 = AgentContext(agent_id="agent-1", version="1.0", owner="owner")
        ctx2 = AgentContext(agent_id="agent-2", version="1.0", owner="owner")

        await cache.set(ctx1, tool_request, sample_grant)

        # ctx1 should hit
        assert await cache.get(ctx1, tool_request) == sample_grant
        # ctx2 should miss
        assert await cache.get(ctx2, tool_request) is CacheEntry

    @pytest.mark.asyncio
    async def test_different_tools_different_keys(
        self, cache, agent_ctx, sample_grant
    ):
        """Test that different tools have different cache keys."""
        req1 = ToolRequest(
            tool="api:fetch", action="get", resource_type="url",
            effect=Effect.READ, params={}
        )
        req2 = ToolRequest(
            tool="api:write", action="put", resource_type="url",
            effect=Effect.WRITE, params={}
        )

        await cache.set(agent_ctx, req1, sample_grant)

        # req1 should hit
        assert await cache.get(agent_ctx, req1) == sample_grant
        # req2 should miss
        assert await cache.get(agent_ctx, req2) is CacheEntry

    @pytest.mark.asyncio
    async def test_ttl_expiration(self, agent_ctx, tool_request, sample_grant):
        """Test that entries expire after TTL."""
        cache = GrantCache(max_size=10, ttl_seconds=0.1)  # 100ms TTL

        await cache.set(agent_ctx, tool_request, sample_grant)

        # Should hit immediately
        assert await cache.get(agent_ctx, tool_request) == sample_grant

        # Wait for expiration
        await asyncio.sleep(0.15)

        # Should miss now
        assert await cache.get(agent_ctx, tool_request) is CacheEntry

    @pytest.mark.asyncio
    async def test_lru_eviction(self, agent_ctx, sample_grant):
        """Test LRU eviction when at capacity."""
        cache = GrantCache(max_size=3, ttl_seconds=60)

        # Fill cache with 3 entries
        for i in range(3):
            req = ToolRequest(
                tool=f"tool-{i}", action="act", resource_type="res",
                effect=Effect.READ, params={}
            )
            await cache.set(agent_ctx, req, sample_grant)

        # Access tool-0 to make it recently used
        req0 = ToolRequest(
            tool="tool-0", action="act", resource_type="res",
            effect=Effect.READ, params={}
        )
        await cache.get(agent_ctx, req0)

        # Add a 4th entry, should evict tool-1 (least recently used)
        req3 = ToolRequest(
            tool="tool-3", action="act", resource_type="res",
            effect=Effect.READ, params={}
        )
        await cache.set(agent_ctx, req3, sample_grant)

        # tool-0 and tool-2 should still be cached
        assert await cache.get(agent_ctx, req0) == sample_grant

        req2 = ToolRequest(
            tool="tool-2", action="act", resource_type="res",
            effect=Effect.READ, params={}
        )
        assert await cache.get(agent_ctx, req2) == sample_grant

        # tool-1 should be evicted
        req1 = ToolRequest(
            tool="tool-1", action="act", resource_type="res",
            effect=Effect.READ, params={}
        )
        assert await cache.get(agent_ctx, req1) is CacheEntry

    @pytest.mark.asyncio
    async def test_invalidate_by_agent_id(
        self, cache, tool_request, sample_grant
    ):
        """Test invalidation by agent_id."""
        ctx1 = AgentContext(agent_id="agent-1", version="1.0", owner="owner")
        ctx2 = AgentContext(agent_id="agent-2", version="1.0", owner="owner")

        await cache.set(ctx1, tool_request, sample_grant)
        await cache.set(ctx2, tool_request, sample_grant)

        # Invalidate agent-1
        count = await cache.invalidate(agent_id="agent-1")
        assert count == 1

        # agent-1 should miss, agent-2 should hit
        assert await cache.get(ctx1, tool_request) is CacheEntry
        assert await cache.get(ctx2, tool_request) == sample_grant

    @pytest.mark.asyncio
    async def test_invalidate_by_tool(self, cache, agent_ctx, sample_grant):
        """Test invalidation by tool prefix."""
        req1 = ToolRequest(
            tool="api:fetch", action="get", resource_type="url",
            effect=Effect.READ, params={}
        )
        req2 = ToolRequest(
            tool="api:write", action="put", resource_type="url",
            effect=Effect.WRITE, params={}
        )
        req3 = ToolRequest(
            tool="mcp:tool", action="run", resource_type="any",
            effect=Effect.READ, params={}
        )

        await cache.set(agent_ctx, req1, sample_grant)
        await cache.set(agent_ctx, req2, sample_grant)
        await cache.set(agent_ctx, req3, sample_grant)

        # Invalidate api:* tools
        count = await cache.invalidate(tool="api:")
        assert count == 2

        # api:* should miss, mcp:* should hit
        assert await cache.get(agent_ctx, req1) is CacheEntry
        assert await cache.get(agent_ctx, req2) is CacheEntry
        assert await cache.get(agent_ctx, req3) == sample_grant

    @pytest.mark.asyncio
    async def test_clear(self, cache, agent_ctx, tool_request, sample_grant):
        """Test clearing all cache entries."""
        await cache.set(agent_ctx, tool_request, sample_grant)

        await cache.clear()

        assert await cache.get(agent_ctx, tool_request) is CacheEntry

    @pytest.mark.asyncio
    async def test_stats(self, cache, agent_ctx, tool_request, sample_grant):
        """Test cache statistics."""
        # Initial stats
        stats = cache.stats
        assert stats["size"] == 0
        assert stats["hits"] == 0
        assert stats["misses"] == 0

        # Add entry and access it
        await cache.set(agent_ctx, tool_request, sample_grant)
        await cache.get(agent_ctx, tool_request)  # Hit
        await cache.get(agent_ctx, tool_request)  # Hit

        # Try missing entry
        other_req = ToolRequest(
            tool="other", action="act", resource_type="res",
            effect=Effect.READ, params={}
        )
        await cache.get(agent_ctx, other_req)  # Miss

        stats = cache.stats
        assert stats["size"] == 1
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 2 / 3


class TestCachedGrantStore:
    """Tests for CachedGrantStore."""

    @pytest.fixture
    def mock_store(self):
        """Create a mock GrantStore."""
        return AsyncMock()

    @pytest.fixture
    def cached_store(self, mock_store, cache):
        """Create a CachedGrantStore instance."""
        return CachedGrantStore(mock_store, cache)

    @pytest.mark.asyncio
    async def test_cache_miss_queries_store(
        self, cached_store, mock_store, agent_ctx, tool_request, sample_grant
    ):
        """Test that cache miss queries underlying store."""
        mock_store.find_matching_grant.return_value = sample_grant

        result = await cached_store.find_matching_grant(agent_ctx, tool_request)

        assert result == sample_grant
        mock_store.find_matching_grant.assert_called_once_with(
            agent_ctx, tool_request
        )

    @pytest.mark.asyncio
    async def test_cache_hit_skips_store(
        self, cached_store, mock_store, cache, agent_ctx, tool_request, sample_grant
    ):
        """Test that cache hit skips underlying store."""
        # Pre-populate cache
        await cache.set(agent_ctx, tool_request, sample_grant)

        result = await cached_store.find_matching_grant(agent_ctx, tool_request)

        assert result == sample_grant
        mock_store.find_matching_grant.assert_not_called()

    @pytest.mark.asyncio
    async def test_caches_store_result(
        self, cached_store, mock_store, cache, agent_ctx, tool_request, sample_grant
    ):
        """Test that store result is cached."""
        mock_store.find_matching_grant.return_value = sample_grant

        # First call - queries store
        await cached_store.find_matching_grant(agent_ctx, tool_request)

        # Second call - should use cache
        await cached_store.find_matching_grant(agent_ctx, tool_request)

        # Store should only be called once
        assert mock_store.find_matching_grant.call_count == 1

    @pytest.mark.asyncio
    async def test_caches_none_result(
        self, cached_store, mock_store, cache, agent_ctx, tool_request
    ):
        """Test that None (no grant) result is cached."""
        mock_store.find_matching_grant.return_value = None

        # First call
        result1 = await cached_store.find_matching_grant(agent_ctx, tool_request)
        # Second call
        result2 = await cached_store.find_matching_grant(agent_ctx, tool_request)

        assert result1 is None
        assert result2 is None
        assert mock_store.find_matching_grant.call_count == 1

    @pytest.mark.asyncio
    async def test_create_grant_invalidates_cache(
        self, cached_store, mock_store, cache, agent_ctx, tool_request, sample_grant
    ):
        """Test that create_grant invalidates relevant cache entries."""
        mock_store.create_grant.return_value = "new-grant-id"

        # Pre-populate cache
        await cache.set(agent_ctx, tool_request, sample_grant)

        # Create new grant
        await cached_store.create_grant(sample_grant)

        # Cache should be invalidated
        cached = await cache.get(agent_ctx, tool_request)
        assert cached is CacheEntry

    @pytest.mark.asyncio
    async def test_revoke_grant_clears_cache(
        self, cached_store, mock_store, cache, agent_ctx, tool_request, sample_grant
    ):
        """Test that revoke_grant clears the entire cache."""
        mock_store.revoke_grant.return_value = True

        # Pre-populate cache
        await cache.set(agent_ctx, tool_request, sample_grant)

        # Revoke grant
        await cached_store.revoke_grant("grant-123")

        # Cache should be cleared
        cached = await cache.get(agent_ctx, tool_request)
        assert cached is CacheEntry

    @pytest.mark.asyncio
    async def test_list_active_grants_not_cached(
        self, cached_store, mock_store
    ):
        """Test that list_active_grants is not cached."""
        mock_store.list_active_grants.return_value = []

        # Multiple calls
        await cached_store.list_active_grants()
        await cached_store.list_active_grants()

        # Should call store each time
        assert mock_store.list_active_grants.call_count == 2

    @pytest.mark.asyncio
    async def test_cache_stats(
        self, cached_store, cache, agent_ctx, tool_request, sample_grant
    ):
        """Test cache_stats property."""
        await cache.set(agent_ctx, tool_request, sample_grant)
        await cache.get(agent_ctx, tool_request)

        stats = cached_store.cache_stats

        assert stats["size"] == 1
        assert stats["hits"] == 1


class TestCacheEntryInternals:
    """Tests for CacheEntry internal behavior."""

    def test_cache_entry_is_expired(self):
        """Test CacheEntry expiration check."""
        entry = CacheEntry(
            value="test",
            expires_at=time.time() - 1,  # Already expired
        )
        assert entry.is_expired is True

        entry2 = CacheEntry(
            value="test",
            expires_at=time.time() + 100,  # Not expired
        )
        assert entry2.is_expired is False

    def test_cache_entry_hits_tracking(self):
        """Test CacheEntry hit counting."""
        entry = CacheEntry(
            value="test",
            expires_at=time.time() + 100,
            hits=0,
        )
        assert entry.hits == 0

        entry.hits += 1
        assert entry.hits == 1
