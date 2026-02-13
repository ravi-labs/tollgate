"""Tests for immutable audit log with hash chaining.

These tests verify tamper-evident audit logging functionality.
"""

import hashlib
import hmac
import os

import pytest

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
from tollgate.security.immutable_audit import ChainedAuditEvent, ImmutableAuditSink


@pytest.fixture
def signing_key():
    """Generate a signing key for tests."""
    return os.urandom(32)


@pytest.fixture
def sample_audit_event():
    """Create a sample audit event."""
    return AuditEvent(
        schema_version="1.0",
        timestamp="2024-01-15T10:00:00Z",
        correlation_id="test-corr-123",
        request_hash="abc123",
        agent=AgentContext(
            agent_id="test-agent",
            version="1.0",
            owner="test-owner",
        ),
        intent=Intent(
            action="test_action",
            reason="Testing",
        ),
        tool_request=ToolRequest(
            tool="api:fetch",
            action="get",
            resource_type="url",
            effect=Effect.READ,
            params={"url": "https://example.com"},
        ),
        decision=Decision(
            decision=DecisionType.ALLOW,
            reason="Test allow",
        ),
        outcome=Outcome.EXECUTED,
    )


@pytest.fixture
def mock_sink():
    """Create a mock sink that collects events."""

    class MockSink:
        def __init__(self):
            self.events = []

        def emit(self, event):
            self.events.append(event.to_dict())

    return MockSink()


class TestChainedAuditEvent:
    """Tests for ChainedAuditEvent dataclass."""

    def test_creates_chained_event(self):
        """Test creating a chained event."""
        event_dict = {"test": "data"}
        chained = ChainedAuditEvent(
            event=event_dict,
            prev_hash="0" * 64,
            event_hash="abc123",
            signature="sig456",
            sequence=1,
        )

        assert chained.event == event_dict
        assert chained.prev_hash == "0" * 64
        assert chained.event_hash == "abc123"
        assert chained.signature == "sig456"
        assert chained.sequence == 1

    def test_to_dict(self):
        """Test converting chained event to dict."""
        event_dict = {"correlation_id": "test-corr-123"}
        chained = ChainedAuditEvent(
            event=event_dict,
            prev_hash="prev",
            event_hash="hash",
            signature="sig",
            sequence=5,
        )

        d = chained.to_dict()

        assert d["_chain"]["prev_hash"] == "prev"
        assert d["_chain"]["event_hash"] == "hash"
        assert d["_chain"]["signature"] == "sig"
        assert d["_chain"]["sequence"] == 5
        assert d["correlation_id"] == "test-corr-123"


class TestImmutableAuditSink:
    """Tests for ImmutableAuditSink."""

    def test_first_event_has_genesis_hash(self, signing_key, mock_sink, sample_audit_event):
        """Test that first event uses genesis hash."""
        sink = ImmutableAuditSink(mock_sink, signing_key)
        sink.emit(sample_audit_event)

        assert len(mock_sink.events) == 1
        chained = mock_sink.events[0]
        assert chained["_chain"]["prev_hash"] == "0" * 64
        assert chained["_chain"]["sequence"] == 0

    def test_second_event_chains_to_first(self, signing_key, mock_sink, sample_audit_event):
        """Test that second event links to first."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        sink.emit(sample_audit_event)
        sink.emit(sample_audit_event)

        assert len(mock_sink.events) == 2
        first = mock_sink.events[0]
        second = mock_sink.events[1]

        assert second["_chain"]["prev_hash"] == first["_chain"]["event_hash"]
        assert second["_chain"]["sequence"] == 1

    def test_event_hash_is_deterministic(self, signing_key, sample_audit_event):
        """Test that event hash is deterministic."""
        mock_sink1 = type("MockSink", (), {"events": [], "emit": lambda self, e: self.events.append(e.to_dict())})()
        mock_sink2 = type("MockSink", (), {"events": [], "emit": lambda self, e: self.events.append(e.to_dict())})()

        sink1 = ImmutableAuditSink(mock_sink1, signing_key)
        sink2 = ImmutableAuditSink(mock_sink2, signing_key)

        sink1.emit(sample_audit_event)
        sink2.emit(sample_audit_event)

        # Same event + same prev_hash should produce same hash
        assert mock_sink1.events[0]["_chain"]["event_hash"] == mock_sink2.events[0]["_chain"]["event_hash"]

    def test_signature_is_valid(self, signing_key, mock_sink, sample_audit_event):
        """Test that signature is valid HMAC."""
        sink = ImmutableAuditSink(mock_sink, signing_key)
        sink.emit(sample_audit_event)

        chained = mock_sink.events[0]
        event_hash = chained["_chain"]["event_hash"]

        # Manually verify the signature
        expected_sig = hmac.new(
            signing_key, event_hash.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        assert chained["_chain"]["signature"] == expected_sig

    def test_chain_of_multiple_events(self, signing_key, mock_sink, sample_audit_event):
        """Test chain integrity with multiple events."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        for i in range(5):
            sink.emit(sample_audit_event)

        assert len(mock_sink.events) == 5

        # Verify chain links
        for i in range(1, 5):
            assert mock_sink.events[i]["_chain"]["prev_hash"] == mock_sink.events[i - 1]["_chain"]["event_hash"]
            assert mock_sink.events[i]["_chain"]["sequence"] == i

    def test_current_hash_property(self, signing_key, mock_sink, sample_audit_event):
        """Test current_hash property."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        # Initially genesis hash
        assert sink.current_hash == "0" * 64

        sink.emit(sample_audit_event)

        # After emission, should be the event hash
        assert sink.current_hash == mock_sink.events[0]["_chain"]["event_hash"]

    def test_sequence_property(self, signing_key, mock_sink, sample_audit_event):
        """Test sequence property."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        assert sink.sequence == 0

        sink.emit(sample_audit_event)
        assert sink.sequence == 1

        sink.emit(sample_audit_event)
        assert sink.sequence == 2


class TestVerifyChain:
    """Tests for verify_chain class method."""

    def test_verify_valid_chain(self, signing_key, mock_sink, sample_audit_event):
        """Test that a valid chain passes verification."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        for _ in range(5):
            sink.emit(sample_audit_event)

        is_valid, error = ImmutableAuditSink.verify_chain(mock_sink.events, signing_key)

        assert is_valid is True
        assert error is None

    def test_verify_empty_chain(self, signing_key):
        """Test that empty chain is valid."""
        is_valid, error = ImmutableAuditSink.verify_chain([], signing_key)

        assert is_valid is True
        assert error is None

    def test_verify_single_event(self, signing_key, mock_sink, sample_audit_event):
        """Test that single event chain is valid."""
        sink = ImmutableAuditSink(mock_sink, signing_key)
        sink.emit(sample_audit_event)

        is_valid, error = ImmutableAuditSink.verify_chain(mock_sink.events, signing_key)

        assert is_valid is True

    def test_detect_tampered_event_hash(self, signing_key, mock_sink, sample_audit_event):
        """Test detection of tampered event hash."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        for _ in range(3):
            sink.emit(sample_audit_event)

        # Tamper with the hash of the second event
        mock_sink.events[1]["_chain"]["event_hash"] = "tampered" + mock_sink.events[1]["_chain"]["event_hash"][8:]

        is_valid, error = ImmutableAuditSink.verify_chain(mock_sink.events, signing_key)

        assert is_valid is False
        assert error is not None

    def test_detect_broken_chain(self, signing_key, mock_sink, sample_audit_event):
        """Test detection of broken chain link."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        for _ in range(3):
            sink.emit(sample_audit_event)

        # Break the chain by modifying prev_hash
        mock_sink.events[2]["_chain"]["prev_hash"] = "wrong" * 16

        is_valid, error = ImmutableAuditSink.verify_chain(mock_sink.events, signing_key)

        assert is_valid is False
        assert "chain" in error.lower() or "prev_hash" in error.lower()

    def test_detect_wrong_signing_key(self, signing_key, mock_sink, sample_audit_event):
        """Test detection of wrong signing key."""
        sink = ImmutableAuditSink(mock_sink, signing_key)
        sink.emit(sample_audit_event)

        wrong_key = os.urandom(32)

        is_valid, error = ImmutableAuditSink.verify_chain(mock_sink.events, wrong_key)

        assert is_valid is False
        assert "signature" in error.lower() or "key" in error.lower()

    def test_detect_sequence_mismatch(self, signing_key, mock_sink, sample_audit_event):
        """Test detection of sequence number mismatch."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        for _ in range(3):
            sink.emit(sample_audit_event)

        # Modify sequence
        mock_sink.events[1]["_chain"]["sequence"] = 99

        is_valid, error = ImmutableAuditSink.verify_chain(mock_sink.events, signing_key)

        assert is_valid is False
        assert "sequence" in error.lower()


class TestImmutableAuditIntegration:
    """Integration tests for immutable audit."""

    def test_different_events_different_hashes(self, signing_key):
        """Test that different events produce different hashes."""
        mock_sink = type("MockSink", (), {"events": [], "emit": lambda self, e: self.events.append(e.to_dict())})()
        sink = ImmutableAuditSink(mock_sink, signing_key)

        event1 = AuditEvent(
            schema_version="1.0",
            timestamp="2024-01-15T10:00:00Z",
            correlation_id="corr-1",
            request_hash="hash1",
            agent=AgentContext(agent_id="agent-1", version="1.0", owner="owner"),
            intent=Intent(action="act1", reason="reason1"),
            tool_request=ToolRequest(
                tool="tool1",
                action="act",
                resource_type="res",
                effect=Effect.READ,
                params={},
            ),
            decision=Decision(decision=DecisionType.ALLOW, reason="ok"),
            outcome=Outcome.EXECUTED,
        )

        event2 = AuditEvent(
            schema_version="1.0",
            timestamp="2024-01-15T10:00:01Z",
            correlation_id="corr-2",
            request_hash="hash2",
            agent=AgentContext(agent_id="agent-2", version="1.0", owner="owner"),
            intent=Intent(action="act2", reason="reason2"),
            tool_request=ToolRequest(
                tool="tool2",
                action="act",
                resource_type="res",
                effect=Effect.WRITE,
                params={},
            ),
            decision=Decision(decision=DecisionType.DENY, reason="no"),
            outcome=Outcome.BLOCKED,
        )

        sink.emit(event1)
        sink.emit(event2)

        assert mock_sink.events[0]["_chain"]["event_hash"] != mock_sink.events[1]["_chain"]["event_hash"]

    def test_audit_log_forensics(self, signing_key, mock_sink, sample_audit_event):
        """Test that audit log supports forensic analysis."""
        sink = ImmutableAuditSink(mock_sink, signing_key)

        # Simulate normal operation
        for _ in range(10):
            sink.emit(sample_audit_event)

        # Verify complete chain
        is_valid, _ = ImmutableAuditSink.verify_chain(mock_sink.events, signing_key)
        assert is_valid

        # Forensic: trace any event back to genesis
        for i, event in enumerate(mock_sink.events):
            assert event["_chain"]["sequence"] == i
            if i > 0:
                assert event["_chain"]["prev_hash"] == mock_sink.events[i - 1]["_chain"]["event_hash"]

    def test_key_too_short_raises(self):
        """Test that a key shorter than 32 bytes raises error."""

        class NoopSink:
            def emit(self, event):
                pass

        mock_sink = NoopSink()

        with pytest.raises(ValueError, match="at least 32 bytes"):
            ImmutableAuditSink(mock_sink, b"short")
