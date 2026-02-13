"""Tests for Agent Reputation System."""

import pytest

from tollgate.reputation import (
    AgentReputation,
    EventType,
    InMemoryReputationStore,
    ReputationAuditSink,
    ReputationConfig,
    ReputationEvent,
    ReputationManager,
    SQLiteReputationStore,
)


class TestReputationConfig:
    """Tests for ReputationConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ReputationConfig()

        assert config.initial_score == 0.5
        assert config.min_score == 0.0
        assert config.max_score == 1.0
        assert config.success_bonus == 0.01
        assert config.failure_penalty == 0.05

    def test_custom_values(self):
        """Test custom configuration."""
        config = ReputationConfig(
            initial_score=0.7,
            success_bonus=0.02,
            failure_penalty=0.1,
        )

        assert config.initial_score == 0.7
        assert config.success_bonus == 0.02
        assert config.failure_penalty == 0.1


class TestReputationEvent:
    """Tests for ReputationEvent."""

    def test_to_dict(self):
        """Test converting event to dictionary."""
        event = ReputationEvent(
            agent_id="agent-1",
            event_type=EventType.SUCCESS,
            timestamp=1234567890.0,
            score_delta=0.01,
            reason="Test success",
            metadata={"tool": "test:tool"},
        )

        d = event.to_dict()

        assert d["agent_id"] == "agent-1"
        assert d["event_type"] == "success"
        assert d["score_delta"] == 0.01
        assert d["metadata"]["tool"] == "test:tool"


class TestAgentReputation:
    """Tests for AgentReputation."""

    def test_to_dict(self):
        """Test converting reputation to dictionary."""
        reputation = AgentReputation(
            agent_id="agent-1",
            score=0.75,
            event_count=100,
            success_count=80,
            failure_count=20,
            violation_count=2,
            last_event_time=1234567890.0,
            last_decay_time=1234567890.0,
            created_at=1234567800.0,
        )

        d = reputation.to_dict()

        assert d["agent_id"] == "agent-1"
        assert d["score"] == 0.75
        assert d["success_count"] == 80

    def test_success_rate(self):
        """Test success rate calculation."""
        reputation = AgentReputation(
            agent_id="agent-1",
            score=0.75,
            event_count=100,
            success_count=80,
            failure_count=20,
            violation_count=0,
            last_event_time=0,
            last_decay_time=0,
            created_at=0,
        )

        assert reputation.success_rate == 0.8

    def test_success_rate_no_events(self):
        """Test success rate with no events."""
        reputation = AgentReputation(
            agent_id="agent-1",
            score=0.5,
            event_count=0,
            success_count=0,
            failure_count=0,
            violation_count=0,
            last_event_time=0,
            last_decay_time=0,
            created_at=0,
        )

        assert reputation.success_rate == 0.0


class TestInMemoryReputationStore:
    """Tests for InMemoryReputationStore."""

    @pytest.fixture
    def store(self):
        """Create an in-memory store."""
        return InMemoryReputationStore()

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, store):
        """Test getting nonexistent reputation."""
        result = await store.get_reputation("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_and_get(self, store):
        """Test updating and getting reputation."""
        reputation = AgentReputation(
            agent_id="agent-1",
            score=0.75,
            event_count=10,
            success_count=8,
            failure_count=2,
            violation_count=0,
            last_event_time=1234567890.0,
            last_decay_time=1234567890.0,
            created_at=1234567800.0,
        )

        await store.update_reputation(reputation)
        result = await store.get_reputation("agent-1")

        assert result is not None
        assert result.score == 0.75
        assert result.success_count == 8

    @pytest.mark.asyncio
    async def test_record_and_get_events(self, store):
        """Test recording and getting events."""
        event = ReputationEvent(
            agent_id="agent-1",
            event_type=EventType.SUCCESS,
            timestamp=1234567890.0,
            score_delta=0.01,
            reason="Test",
        )

        await store.record_event(event)
        events = await store.get_events("agent-1")

        assert len(events) == 1
        assert events[0].event_type == EventType.SUCCESS


class TestSQLiteReputationStore:
    """Tests for SQLiteReputationStore."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a SQLite store."""
        return SQLiteReputationStore(tmp_path / "reputation.db")

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, store):
        """Test getting nonexistent reputation."""
        result = await store.get_reputation("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_and_get(self, store):
        """Test updating and getting reputation."""
        reputation = AgentReputation(
            agent_id="agent-1",
            score=0.75,
            event_count=10,
            success_count=8,
            failure_count=2,
            violation_count=0,
            last_event_time=1234567890.0,
            last_decay_time=1234567890.0,
            created_at=1234567800.0,
        )

        await store.update_reputation(reputation)
        result = await store.get_reputation("agent-1")

        assert result is not None
        assert result.score == 0.75

    @pytest.mark.asyncio
    async def test_record_and_get_events(self, store):
        """Test recording and getting events."""
        # First create a reputation record
        reputation = AgentReputation(
            agent_id="agent-1",
            score=0.5,
            event_count=0,
            success_count=0,
            failure_count=0,
            violation_count=0,
            last_event_time=0,
            last_decay_time=0,
            created_at=1234567800.0,
        )
        await store.update_reputation(reputation)

        event = ReputationEvent(
            agent_id="agent-1",
            event_type=EventType.SUCCESS,
            timestamp=1234567890.0,
            score_delta=0.01,
            reason="Test",
        )

        await store.record_event(event)
        events = await store.get_events("agent-1")

        assert len(events) == 1
        assert events[0].event_type == EventType.SUCCESS

    @pytest.mark.asyncio
    async def test_get_events_with_limit(self, store):
        """Test getting events with limit."""
        reputation = AgentReputation(
            agent_id="agent-1",
            score=0.5,
            event_count=0,
            success_count=0,
            failure_count=0,
            violation_count=0,
            last_event_time=0,
            last_decay_time=0,
            created_at=0,
        )
        await store.update_reputation(reputation)

        # Record multiple events
        for i in range(10):
            event = ReputationEvent(
                agent_id="agent-1",
                event_type=EventType.SUCCESS,
                timestamp=float(i),
                score_delta=0.01,
            )
            await store.record_event(event)

        events = await store.get_events("agent-1", limit=5)
        assert len(events) == 5


class TestReputationManager:
    """Tests for ReputationManager."""

    @pytest.fixture
    def manager(self):
        """Create a reputation manager."""
        return ReputationManager(ReputationConfig())

    @pytest.mark.asyncio
    async def test_initial_score(self, manager):
        """Test initial score for new agent."""
        score = await manager.get_score("new-agent")
        assert score == 0.5

    @pytest.mark.asyncio
    async def test_record_success(self, manager):
        """Test recording success increases score."""
        initial = await manager.get_score("agent-1")

        await manager.record_success("agent-1")

        new_score = await manager.get_score("agent-1")
        assert new_score > initial

    @pytest.mark.asyncio
    async def test_record_failure(self, manager):
        """Test recording failure decreases score."""
        # First record some successes to raise score
        for _ in range(5):
            await manager.record_success("agent-1")

        score_before = await manager.get_score("agent-1")
        await manager.record_failure("agent-1")
        score_after = await manager.get_score("agent-1")

        assert score_after < score_before

    @pytest.mark.asyncio
    async def test_record_policy_violation(self, manager):
        """Test recording policy violation significantly decreases score."""
        for _ in range(10):
            await manager.record_success("agent-1")

        score_before = await manager.get_score("agent-1")
        await manager.record_policy_violation("agent-1")
        score_after = await manager.get_score("agent-1")

        # Violation penalty should be larger than failure
        assert score_before - score_after >= 0.1

    @pytest.mark.asyncio
    async def test_score_bounds(self, manager):
        """Test that score stays within bounds."""
        # Try to exceed max
        for _ in range(200):
            await manager.record_success("agent-1")

        score = await manager.get_score("agent-1")
        assert score <= 1.0

        # Try to go below min
        for _ in range(100):
            await manager.record_policy_violation("agent-2")

        score = await manager.get_score("agent-2")
        assert score >= 0.0

    @pytest.mark.asyncio
    async def test_can_perform_high_trust(self, manager):
        """Test can_perform for high-trust operations."""
        # New agent shouldn't be able to perform high-trust operations
        can = await manager.can_perform("new-agent", min_score=0.8)
        assert can is False

        # Build up reputation
        for _ in range(50):
            await manager.record_success("trusted-agent")

        can = await manager.can_perform("trusted-agent", min_score=0.8)
        assert can is True

    @pytest.mark.asyncio
    async def test_is_low_trust(self, manager):
        """Test low trust detection."""
        # New agent is not low trust
        is_low = await manager.is_low_trust("new-agent")
        assert is_low is False

        # Many failures lead to low trust
        for _ in range(20):
            await manager.record_policy_violation("bad-agent")

        is_low = await manager.is_low_trust("bad-agent")
        assert is_low is True

    @pytest.mark.asyncio
    async def test_get_reputation(self, manager):
        """Test getting full reputation data."""
        await manager.record_success("agent-1")
        await manager.record_success("agent-1")
        await manager.record_failure("agent-1")

        reputation = await manager.get_reputation("agent-1")

        assert reputation is not None
        assert reputation.event_count == 3
        assert reputation.success_count == 2
        assert reputation.failure_count == 1

    @pytest.mark.asyncio
    async def test_rate_limit_factor_low_trust(self, manager):
        """Test rate limit factor for low-trust agent."""
        # Create low-trust agent
        for _ in range(20):
            await manager.record_policy_violation("bad-agent")

        factor = await manager.get_rate_limit_factor("bad-agent")

        assert factor < 1.0
        assert factor == manager.config.low_trust_rate_limit

    @pytest.mark.asyncio
    async def test_rate_limit_factor_high_trust(self, manager):
        """Test rate limit factor for high-trust agent."""
        # Create high-trust agent
        for _ in range(50):
            await manager.record_success("good-agent")

        factor = await manager.get_rate_limit_factor("good-agent")

        assert factor == 1.0


class TestReputationDecay:
    """Tests for reputation decay."""

    @pytest.mark.asyncio
    async def test_decay_toward_initial(self):
        """Test that scores decay toward initial value."""
        config = ReputationConfig(
            initial_score=0.5,
            decay_rate=1.0,  # Fast decay for testing
            decay_interval_hours=0.0001,  # Very short interval for testing
        )
        manager = ReputationManager(config)

        # Build up high score
        for _ in range(50):
            await manager.record_success("agent-1")

        score_before = await manager.get_score("agent-1")
        assert score_before > 0.5

        # Simulate time passing by manually updating last_decay_time
        reputation = await manager.store.get_reputation("agent-1")
        import time
        old_reputation = AgentReputation(
            agent_id=reputation.agent_id,
            score=reputation.score,
            event_count=reputation.event_count,
            success_count=reputation.success_count,
            failure_count=reputation.failure_count,
            violation_count=reputation.violation_count,
            last_event_time=reputation.last_event_time,
            last_decay_time=time.time() - 3600,  # 1 hour ago
            created_at=reputation.created_at,
        )
        await manager.store.update_reputation(old_reputation)

        # Get score again - should trigger decay
        score_after = await manager.get_score("agent-1")

        # Score should have moved toward initial
        assert score_after < score_before


class TestReputationAuditSink:
    """Tests for ReputationAuditSink."""

    @pytest.fixture
    def manager(self):
        """Create a reputation manager."""
        return ReputationManager()

    @pytest.fixture
    def sink(self, manager):
        """Create an audit sink."""
        return ReputationAuditSink(manager)

    @pytest.mark.asyncio
    async def test_process_success(self, manager, sink):
        """Test processing successful execution."""
        from datetime import datetime, timezone

        from tollgate import (
            AgentContext,
            AuditEvent,
            Decision,
            DecisionType,
            Effect,
            Intent,
            Outcome,
            ToolRequest,
        )

        event = AuditEvent(
            correlation_id="test-123",
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_hash="hash-123",
            agent=AgentContext(
                agent_id="test-agent",
                version="1.0",
                owner="test",
            ),
            intent=Intent(action="test", reason="testing"),
            tool_request=ToolRequest(
                tool="test:tool",
                action="test",
                resource_type="test",
                effect=Effect.READ,
                params={},
            ),
            decision=Decision(
                decision=DecisionType.ALLOW,
                reason="Allowed",
            ),
            outcome=Outcome.EXECUTED,
        )

        # Process event
        await sink._process_event(event)

        # Check reputation was updated
        reputation = await manager.get_reputation("test-agent")
        assert reputation is not None
        assert reputation.success_count == 1

    @pytest.mark.asyncio
    async def test_process_denial(self, manager, sink):
        """Test processing policy denial."""
        from datetime import datetime, timezone

        from tollgate import (
            AgentContext,
            AuditEvent,
            Decision,
            DecisionType,
            Effect,
            Intent,
            Outcome,
            ToolRequest,
        )

        event = AuditEvent(
            correlation_id="test-456",
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_hash="hash-456",
            agent=AgentContext(
                agent_id="bad-agent",
                version="1.0",
                owner="test",
            ),
            intent=Intent(action="test", reason="testing"),
            tool_request=ToolRequest(
                tool="test:tool",
                action="delete",
                resource_type="test",
                effect=Effect.DELETE,
                params={},
            ),
            decision=Decision(
                decision=DecisionType.DENY,
                reason="Not allowed",
            ),
            outcome=Outcome.BLOCKED,
        )

        # Process event
        await sink._process_event(event)

        # Check reputation was updated
        reputation = await manager.get_reputation("bad-agent")
        assert reputation is not None
        assert reputation.violation_count == 1
        assert reputation.score < 0.5  # Below initial
