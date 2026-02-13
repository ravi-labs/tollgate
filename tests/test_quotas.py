"""Tests for tenant quota management system."""

import pytest

from tollgate.tenancy.quotas import (
    InMemoryQuotaStore,
    QuotaEnforcer,
    QuotaExceededError,
    QuotaUsage,
    TenantQuotas,
)


@pytest.fixture
def quota_store():
    """Create an InMemoryQuotaStore instance."""
    return InMemoryQuotaStore()


@pytest.fixture
def enforcer(quota_store):
    """Create a QuotaEnforcer instance."""
    default_quotas = TenantQuotas(max_tool_calls_per_hour=10)
    return QuotaEnforcer(quota_store, default_quotas=default_quotas)


class TestTenantQuotas:
    """Tests for TenantQuotas dataclass."""

    def test_default_values(self):
        """Test that TenantQuotas has sensible defaults."""
        quotas = TenantQuotas()

        assert quotas.max_tool_calls_per_hour is None
        assert quotas.max_tool_calls_per_day is None
        assert quotas.max_grants_per_day is None
        assert quotas.max_active_grants is None
        assert quotas.max_agents is None
        assert quotas.max_approvals_per_hour is None
        assert quotas.custom == {}

    def test_custom_values(self):
        """Test TenantQuotas with custom values."""
        quotas = TenantQuotas(
            max_tool_calls_per_hour=1000,
            max_grants_per_day=50,
            max_agents=10,
        )

        assert quotas.max_tool_calls_per_hour == 1000
        assert quotas.max_grants_per_day == 50
        assert quotas.max_agents == 10

    def test_get_limit(self):
        """Test getting limits by quota type."""
        quotas = TenantQuotas(
            max_tool_calls_per_hour=100,
            custom={"special_quota": 25},
        )

        assert quotas.get_limit("max_tool_calls_per_hour") == 100
        assert quotas.get_limit("special_quota") == 25
        assert quotas.get_limit("nonexistent") is None

    def test_to_dict(self):
        """Test converting quotas to dict."""
        quotas = TenantQuotas(max_tool_calls_per_hour=100)
        d = quotas.to_dict()

        assert d["max_tool_calls_per_hour"] == 100
        assert d["max_tool_calls_per_day"] is None
        assert "custom" in d


class TestInMemoryQuotaStore:
    """Tests for InMemoryQuotaStore."""

    @pytest.mark.asyncio
    async def test_initial_usage_is_zero(self, quota_store):
        """Test that initial usage is zero."""
        usage = await quota_store.get_usage("org-1", "tool_calls", window_seconds=3600)
        assert usage == 0

    @pytest.mark.asyncio
    async def test_increment_increases_usage(self, quota_store):
        """Test that increment increases usage."""
        await quota_store.increment("org-1", "tool_calls", window_seconds=3600)
        usage = await quota_store.get_usage("org-1", "tool_calls", window_seconds=3600)
        assert usage == 1

        await quota_store.increment("org-1", "tool_calls", window_seconds=3600)
        usage = await quota_store.get_usage("org-1", "tool_calls", window_seconds=3600)
        assert usage == 2

    @pytest.mark.asyncio
    async def test_increment_with_amount(self, quota_store):
        """Test increment with custom amount."""
        await quota_store.increment("org-1", "tool_calls", window_seconds=3600, amount=5)
        usage = await quota_store.get_usage("org-1", "tool_calls", window_seconds=3600)
        assert usage == 5

    @pytest.mark.asyncio
    async def test_separate_orgs(self, quota_store):
        """Test that orgs have separate counters."""
        await quota_store.increment("org-1", "tool_calls", window_seconds=3600)
        await quota_store.increment("org-2", "tool_calls", window_seconds=3600)

        usage1 = await quota_store.get_usage("org-1", "tool_calls", window_seconds=3600)
        usage2 = await quota_store.get_usage("org-2", "tool_calls", window_seconds=3600)

        assert usage1 == 1
        assert usage2 == 1

    @pytest.mark.asyncio
    async def test_separate_quota_types(self, quota_store):
        """Test that quota types have separate counters."""
        await quota_store.increment("org-1", "tool_calls", window_seconds=3600)
        await quota_store.increment("org-1", "grants", window_seconds=3600)

        usage_calls = await quota_store.get_usage("org-1", "tool_calls", window_seconds=3600)
        usage_grants = await quota_store.get_usage("org-1", "grants", window_seconds=3600)

        assert usage_calls == 1
        assert usage_grants == 1

    @pytest.mark.asyncio
    async def test_reset(self, quota_store):
        """Test resetting quota usage."""
        await quota_store.increment("org-1", "tool_calls", window_seconds=3600, amount=100)
        await quota_store.reset("org-1", "tool_calls")

        usage = await quota_store.get_usage("org-1", "tool_calls", window_seconds=3600)
        assert usage == 0

    @pytest.mark.asyncio
    async def test_reset_all_for_org(self, quota_store):
        """Test resetting all quotas for an org."""
        await quota_store.increment("org-1", "tool_calls", window_seconds=3600, amount=10)
        await quota_store.increment("org-1", "grants", window_seconds=3600, amount=5)
        await quota_store.reset("org-1")

        assert await quota_store.get_usage("org-1", "tool_calls", window_seconds=3600) == 0
        assert await quota_store.get_usage("org-1", "grants", window_seconds=3600) == 0


class TestQuotaEnforcer:
    """Tests for QuotaEnforcer."""

    @pytest.mark.asyncio
    async def test_allows_when_under_limit(self, enforcer):
        """Test that requests under limit are allowed."""
        # Default quota is max_tool_calls_per_hour=10
        for i in range(10):
            result = await enforcer.check_and_increment(
                "org-1", "max_tool_calls_per_hour"
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_denies_when_at_limit(self, enforcer):
        """Test that requests at limit are denied."""
        # Use up the quota
        for _ in range(10):
            await enforcer.check_and_increment("org-1", "max_tool_calls_per_hour")

        # Next request should fail
        result = await enforcer.check_and_increment("org-1", "max_tool_calls_per_hour")
        assert result is False

    @pytest.mark.asyncio
    async def test_allows_when_no_limit(self, quota_store):
        """Test that requests are allowed when no limit is set."""
        enforcer = QuotaEnforcer(quota_store)  # No default quotas

        for _ in range(100):
            result = await enforcer.check_and_increment("org-1", "max_tool_calls_per_hour")
            assert result is True

    @pytest.mark.asyncio
    async def test_check_quota(self, enforcer):
        """Test checking quota without incrementing."""
        usage = await enforcer.check_quota("org-1", "max_tool_calls_per_hour")

        assert isinstance(usage, QuotaUsage)
        assert usage.current == 0
        assert usage.limit == 10
        assert usage.remaining == 10
        assert usage.is_exceeded is False

    @pytest.mark.asyncio
    async def test_raises_on_exceeded(self, enforcer):
        """Test raising exception when quota exceeded."""
        # Use up the quota
        for _ in range(10):
            await enforcer.check_and_increment("org-1", "max_tool_calls_per_hour")

        # Next request should raise
        with pytest.raises(QuotaExceededError) as exc_info:
            await enforcer.check_and_increment(
                "org-1", "max_tool_calls_per_hour", raise_on_exceeded=True
            )

        assert exc_info.value.org_id == "org-1"
        assert exc_info.value.limit == 10

    @pytest.mark.asyncio
    async def test_set_tenant_quotas(self, quota_store):
        """Test setting custom quotas per tenant."""
        enforcer = QuotaEnforcer(quota_store)
        custom_quotas = TenantQuotas(max_tool_calls_per_hour=5)
        enforcer.set_tenant_quotas("org-premium", custom_quotas)

        # Premium org should have custom limit
        quotas = enforcer.get_quotas("org-premium")
        assert quotas.max_tool_calls_per_hour == 5


class TestQuotaExceededError:
    """Tests for QuotaExceededError."""

    def test_error_message(self):
        """Test error message formatting."""
        error = QuotaExceededError(
            org_id="org-123",
            quota_type="tool_calls",
            limit=100,
            current=100,
        )

        assert "org-123" in str(error)
        assert "tool_calls" in str(error)
        assert "100" in str(error)

    def test_error_attributes(self):
        """Test error attributes."""
        error = QuotaExceededError(
            org_id="org-123",
            quota_type="grants",
            limit=50,
            current=50,
        )

        assert error.org_id == "org-123"
        assert error.quota_type == "grants"
        assert error.limit == 50
        assert error.current == 50

    def test_is_tollgate_error(self):
        """Test that QuotaExceededError is a TollgateError."""
        from tollgate import TollgateError

        error = QuotaExceededError("org", "type", 10, 10)
        assert isinstance(error, TollgateError)


class TestQuotaUsage:
    """Tests for QuotaUsage dataclass."""

    def test_remaining_with_limit(self):
        """Test remaining calculation."""
        usage = QuotaUsage(
            org_id="org-1",
            quota_type="tool_calls",
            current=30,
            limit=100,
            window_start=0.0,
            window_seconds=3600,
        )

        assert usage.remaining == 70

    def test_remaining_without_limit(self):
        """Test remaining when no limit."""
        usage = QuotaUsage(
            org_id="org-1",
            quota_type="tool_calls",
            current=30,
            limit=None,
            window_start=0.0,
            window_seconds=3600,
        )

        assert usage.remaining is None

    def test_is_exceeded(self):
        """Test is_exceeded property."""
        usage_ok = QuotaUsage(
            org_id="org-1",
            quota_type="tool_calls",
            current=50,
            limit=100,
            window_start=0.0,
            window_seconds=3600,
        )
        assert usage_ok.is_exceeded is False

        usage_exceeded = QuotaUsage(
            org_id="org-1",
            quota_type="tool_calls",
            current=100,
            limit=100,
            window_start=0.0,
            window_seconds=3600,
        )
        assert usage_exceeded.is_exceeded is True


class TestQuotaEnforcerIntegration:
    """Integration tests for quota enforcement."""

    @pytest.mark.asyncio
    async def test_multi_org_quota_isolation(self, quota_store):
        """Test that quotas are isolated between orgs."""
        quotas = TenantQuotas(max_tool_calls_per_hour=5)
        enforcer = QuotaEnforcer(quota_store, default_quotas=quotas)

        # Org 1 uses all quota
        for _ in range(5):
            await enforcer.check_and_increment("org-1", "max_tool_calls_per_hour")

        # Org 1 is at limit
        result = await enforcer.check_and_increment("org-1", "max_tool_calls_per_hour")
        assert result is False

        # Org 2 should still have full quota
        result = await enforcer.check_and_increment("org-2", "max_tool_calls_per_hour")
        assert result is True

    @pytest.mark.asyncio
    async def test_different_quota_types(self, quota_store):
        """Test different quota types are tracked separately."""
        quotas = TenantQuotas(
            max_tool_calls_per_hour=100,
            max_grants_per_day=10,
        )
        enforcer = QuotaEnforcer(quota_store, default_quotas=quotas)

        # Use all grants
        for _ in range(10):
            await enforcer.check_and_increment("org-1", "max_grants_per_day")

        # Grants exhausted
        result = await enforcer.check_and_increment("org-1", "max_grants_per_day")
        assert result is False

        # Tool calls still available
        result = await enforcer.check_and_increment("org-1", "max_tool_calls_per_hour")
        assert result is True
