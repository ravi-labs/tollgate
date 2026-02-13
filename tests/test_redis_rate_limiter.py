"""Tests for Redis Rate Limiter.

These tests require a running Redis instance. They are skipped if Redis
is not available.
"""


import pytest

redis = pytest.importorskip("redis")

from tollgate import AgentContext, Effect, ToolRequest
from tollgate.backends import RedisRateLimiter


@pytest.fixture
def redis_url():
    """Get Redis URL for testing."""
    return "redis://localhost:6379/15"  # Use DB 15 for testing


@pytest.fixture
async def redis_client(redis_url):
    """Create a Redis client for testing."""
    import redis.asyncio as aioredis

    client = aioredis.from_url(redis_url, decode_responses=True)

    # Check if Redis is available
    try:
        await client.ping()
    except Exception:
        pytest.skip("Redis not available")

    yield client

    # Cleanup
    await client.flushdb()
    await client.close()


@pytest.fixture
def rate_limiter(redis_url):
    """Create a RedisRateLimiter instance."""
    rules = [
        {
            "agent_id": "*",
            "tool": "*",
            "max_calls": 5,
            "window_seconds": 10,
        },
        {
            "effect": "write",
            "max_calls": 2,
            "window_seconds": 10,
        },
    ]

    return RedisRateLimiter(redis_url=redis_url, rules=rules)


@pytest.fixture
def agent_ctx():
    """Create a test agent context."""
    return AgentContext(
        agent_id="test-agent",
        version="1.0",
        owner="test-owner",
    )


@pytest.fixture
def read_request():
    """Create a read tool request."""
    return ToolRequest(
        tool="api:fetch",
        action="get",
        resource_type="url",
        effect=Effect.READ,
        params={},
    )


@pytest.fixture
def write_request():
    """Create a write tool request."""
    return ToolRequest(
        tool="api:update",
        action="put",
        resource_type="record",
        effect=Effect.WRITE,
        params={},
    )


@pytest.mark.asyncio
async def test_rate_limiter_allows_within_limit(
    rate_limiter, redis_client, agent_ctx, read_request
):
    """Test that requests within limit are allowed."""
    # Should allow 5 requests
    for i in range(5):
        allowed, reason, retry_after = await rate_limiter.check_rate_limit(
            agent_ctx, read_request
        )
        assert allowed, f"Request {i+1} should be allowed"
        assert reason is None
        assert retry_after is None

    await rate_limiter.close()


@pytest.mark.asyncio
async def test_rate_limiter_blocks_over_limit(
    rate_limiter, redis_client, agent_ctx, read_request
):
    """Test that requests over limit are blocked."""
    # Make 5 allowed requests
    for _ in range(5):
        await rate_limiter.check_rate_limit(agent_ctx, read_request)

    # 6th should be blocked
    allowed, reason, retry_after = await rate_limiter.check_rate_limit(
        agent_ctx, read_request
    )

    assert not allowed
    assert "Rate limit exceeded" in reason
    assert retry_after is not None
    assert retry_after > 0

    await rate_limiter.close()


@pytest.mark.asyncio
async def test_rate_limiter_separate_rules(
    rate_limiter, redis_client, agent_ctx, read_request, write_request
):
    """Test that different rules apply separately."""
    # Write rule has max_calls=2
    for i in range(2):
        allowed, _, _ = await rate_limiter.check_rate_limit(agent_ctx, write_request)
        assert allowed, f"Write request {i+1} should be allowed"

    # 3rd write should be blocked by write rule
    allowed, reason, _ = await rate_limiter.check_rate_limit(agent_ctx, write_request)
    assert not allowed
    assert "effect=write" in reason

    await rate_limiter.close()


@pytest.mark.asyncio
async def test_rate_limiter_per_agent(redis_url, redis_client, read_request):
    """Test that limits are per-agent."""
    rules = [{"agent_id": "*", "tool": "*", "max_calls": 3, "window_seconds": 10}]
    rate_limiter = RedisRateLimiter(redis_url=redis_url, rules=rules)

    ctx1 = AgentContext(agent_id="agent-1", version="1.0", owner="user")
    ctx2 = AgentContext(agent_id="agent-2", version="1.0", owner="user")

    # Both agents should get their own limits
    for _ in range(3):
        allowed1, _, _ = await rate_limiter.check_rate_limit(ctx1, read_request)
        allowed2, _, _ = await rate_limiter.check_rate_limit(ctx2, read_request)
        assert allowed1
        assert allowed2

    # Both should be blocked now
    allowed1, _, _ = await rate_limiter.check_rate_limit(ctx1, read_request)
    allowed2, _, _ = await rate_limiter.check_rate_limit(ctx2, read_request)

    assert not allowed1
    assert not allowed2

    await rate_limiter.close()


@pytest.mark.asyncio
async def test_rate_limiter_org_isolation(redis_url, redis_client, read_request):
    """Test that org_id isolates rate limits."""
    rules = [{"org_id": "*", "tool": "*", "max_calls": 3, "window_seconds": 10}]
    rate_limiter = RedisRateLimiter(redis_url=redis_url, rules=rules)

    ctx1 = AgentContext.with_org(
        agent_id="agent", version="1.0", owner="user", org_id="org-a"
    )
    ctx2 = AgentContext.with_org(
        agent_id="agent", version="1.0", owner="user", org_id="org-b"
    )

    # Same agent, different orgs - should have separate limits
    for _ in range(3):
        allowed1, _, _ = await rate_limiter.check_rate_limit(ctx1, read_request)
        allowed2, _, _ = await rate_limiter.check_rate_limit(ctx2, read_request)
        assert allowed1
        assert allowed2

    await rate_limiter.close()


@pytest.mark.asyncio
async def test_get_usage(rate_limiter, redis_client, agent_ctx, read_request):
    """Test getting current usage."""
    # Make some requests
    for _ in range(3):
        await rate_limiter.check_rate_limit(agent_ctx, read_request)

    usage = await rate_limiter.get_usage(agent_ctx, read_request)

    # Should have usage info for matching rules
    assert len(usage) > 0

    # Check one of the usages
    for rule_desc, info in usage.items():
        assert info["current"] == 3
        assert info["max"] == 5
        assert info["remaining"] == 2
        break

    await rate_limiter.close()


@pytest.mark.asyncio
async def test_reset(rate_limiter, redis_client, agent_ctx, read_request):
    """Test resetting rate limit state."""
    # Make some requests
    for _ in range(5):
        await rate_limiter.check_rate_limit(agent_ctx, read_request)

    # Should be blocked
    allowed, _, _ = await rate_limiter.check_rate_limit(agent_ctx, read_request)
    assert not allowed

    # Reset
    deleted = await rate_limiter.reset(agent_id="test-agent")
    assert deleted > 0

    # Should be allowed again
    allowed, _, _ = await rate_limiter.check_rate_limit(agent_ctx, read_request)
    assert allowed

    await rate_limiter.close()


@pytest.mark.asyncio
async def test_get_all_buckets(rate_limiter, redis_client, agent_ctx, read_request):
    """Test getting all active buckets."""
    # Make some requests
    await rate_limiter.check_rate_limit(agent_ctx, read_request)

    buckets = await rate_limiter.get_all_buckets()

    assert len(buckets) > 0
    bucket = buckets[0]
    assert "actual_agent" in bucket
    assert bucket["current_count"] >= 1

    await rate_limiter.close()


@pytest.mark.asyncio
async def test_tool_prefix_matching(redis_url, redis_client):
    """Test tool prefix matching in rules."""
    rules = [{"tool": "api:*", "max_calls": 2, "window_seconds": 10}]
    rate_limiter = RedisRateLimiter(redis_url=redis_url, rules=rules)

    ctx = AgentContext(agent_id="test", version="1.0", owner="user")

    req1 = ToolRequest(
        tool="api:fetch", action="get", resource_type="url", effect=Effect.READ, params={}
    )
    req2 = ToolRequest(
        tool="api:update", action="put", resource_type="url", effect=Effect.WRITE, params={}
    )
    req3 = ToolRequest(
        tool="mcp:tool", action="run", resource_type="any", effect=Effect.READ, params={}
    )

    # api:* should match api:fetch and api:update
    allowed1, _, _ = await rate_limiter.check_rate_limit(ctx, req1)
    allowed2, _, _ = await rate_limiter.check_rate_limit(ctx, req2)
    assert allowed1
    assert allowed2

    # mcp:tool should not match api:* rule (no rule, so allowed)
    allowed3, _, _ = await rate_limiter.check_rate_limit(ctx, req3)
    assert allowed3

    # api:* limit should be reached
    allowed4, _, _ = await rate_limiter.check_rate_limit(ctx, req1)
    assert not allowed4

    await rate_limiter.close()
