"""Tests for Ed25519 agent verification.

These tests require the cryptography package. They are skipped if
cryptography is not available.
"""

import pytest

cryptography = pytest.importorskip("cryptography")

from tollgate import AgentContext
from tollgate.verification import (
    generate_ed25519_keypair,
    make_ed25519_verifier,
    sign_agent_context_ed25519,
    verify_agent_context_ed25519,
)


@pytest.fixture
def keypair():
    """Generate a test keypair."""
    return generate_ed25519_keypair()


@pytest.fixture
def agent_ctx():
    """Create a test agent context."""
    return AgentContext(
        agent_id="test-agent",
        version="1.0.0",
        owner="test-owner",
    )


class TestGenerateKeypair:
    """Tests for generate_ed25519_keypair."""

    def test_generates_valid_keys(self):
        """Test that generated keys are valid."""
        private_key, public_key = generate_ed25519_keypair()

        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert len(private_key) == 32
        assert len(public_key) == 32

    def test_generates_unique_keys(self):
        """Test that each call generates unique keys."""
        keypair1 = generate_ed25519_keypair()
        keypair2 = generate_ed25519_keypair()

        assert keypair1[0] != keypair2[0]  # Private keys differ
        assert keypair1[1] != keypair2[1]  # Public keys differ


class TestSignAgentContext:
    """Tests for sign_agent_context_ed25519."""

    def test_signs_agent_context(self, keypair, agent_ctx):
        """Test that signing adds a signature to metadata."""
        private_key, _ = keypair

        signed_ctx = sign_agent_context_ed25519(agent_ctx, private_key)

        assert "_ed25519_signature" in signed_ctx.metadata
        assert isinstance(signed_ctx.metadata["_ed25519_signature"], str)
        assert len(signed_ctx.metadata["_ed25519_signature"]) == 128  # 64 bytes hex

    def test_preserves_existing_metadata(self, keypair, agent_ctx):
        """Test that signing preserves existing metadata."""
        private_key, _ = keypair

        ctx_with_meta = AgentContext(
            agent_id="test-agent",
            version="1.0.0",
            owner="test-owner",
            metadata={"custom_field": "value", "number": 42},
        )

        signed_ctx = sign_agent_context_ed25519(ctx_with_meta, private_key)

        assert signed_ctx.metadata["custom_field"] == "value"
        assert signed_ctx.metadata["number"] == 42
        assert "_ed25519_signature" in signed_ctx.metadata

    def test_does_not_modify_original(self, keypair, agent_ctx):
        """Test that signing returns a new context without modifying original."""
        private_key, _ = keypair

        signed_ctx = sign_agent_context_ed25519(agent_ctx, private_key)

        assert "_ed25519_signature" not in agent_ctx.metadata
        assert "_ed25519_signature" in signed_ctx.metadata

    def test_deterministic_for_same_key_and_context(self, keypair, agent_ctx):
        """Test that the same key and context produce the same signature."""
        private_key, _ = keypair

        sig1 = sign_agent_context_ed25519(agent_ctx, private_key)
        sig2 = sign_agent_context_ed25519(agent_ctx, private_key)

        # Ed25519 signatures are deterministic (no nonce)
        assert sig1.metadata["_ed25519_signature"] == sig2.metadata["_ed25519_signature"]

    def test_different_contexts_produce_different_signatures(self, keypair):
        """Test that different contexts produce different signatures."""
        private_key, _ = keypair

        ctx1 = AgentContext(agent_id="agent-1", version="1.0", owner="owner")
        ctx2 = AgentContext(agent_id="agent-2", version="1.0", owner="owner")

        sig1 = sign_agent_context_ed25519(ctx1, private_key)
        sig2 = sign_agent_context_ed25519(ctx2, private_key)

        assert sig1.metadata["_ed25519_signature"] != sig2.metadata["_ed25519_signature"]


class TestVerifyAgentContext:
    """Tests for verify_agent_context_ed25519."""

    def test_verifies_valid_signature(self, keypair, agent_ctx):
        """Test that a valid signature is verified."""
        private_key, public_key = keypair

        signed_ctx = sign_agent_context_ed25519(agent_ctx, private_key)
        is_valid = verify_agent_context_ed25519(signed_ctx, public_key)

        assert is_valid is True

    def test_rejects_missing_signature(self, keypair, agent_ctx):
        """Test that missing signature is rejected."""
        _, public_key = keypair

        is_valid = verify_agent_context_ed25519(agent_ctx, public_key)

        assert is_valid is False

    def test_rejects_invalid_signature(self, keypair, agent_ctx):
        """Test that an invalid signature is rejected."""
        _, public_key = keypair

        # Create a context with an invalid signature
        ctx_with_bad_sig = AgentContext(
            agent_id="test-agent",
            version="1.0.0",
            owner="test-owner",
            metadata={"_ed25519_signature": "00" * 64},  # Invalid signature
        )

        is_valid = verify_agent_context_ed25519(ctx_with_bad_sig, public_key)

        assert is_valid is False

    def test_rejects_tampered_context(self, keypair, agent_ctx):
        """Test that a tampered context fails verification."""
        private_key, public_key = keypair

        signed_ctx = sign_agent_context_ed25519(agent_ctx, private_key)

        # Tamper with the agent_id
        from dataclasses import replace

        tampered_ctx = replace(signed_ctx, agent_id="tampered-agent")

        is_valid = verify_agent_context_ed25519(tampered_ctx, public_key)

        assert is_valid is False

    def test_rejects_wrong_public_key(self, keypair, agent_ctx):
        """Test that verification fails with the wrong public key."""
        private_key, _ = keypair
        _, wrong_public_key = generate_ed25519_keypair()

        signed_ctx = sign_agent_context_ed25519(agent_ctx, private_key)
        is_valid = verify_agent_context_ed25519(signed_ctx, wrong_public_key)

        assert is_valid is False

    def test_rejects_malformed_signature_hex(self, keypair, agent_ctx):
        """Test that malformed hex signature is rejected."""
        _, public_key = keypair

        ctx_with_bad_hex = AgentContext(
            agent_id="test-agent",
            version="1.0.0",
            owner="test-owner",
            metadata={"_ed25519_signature": "not-valid-hex"},
        )

        is_valid = verify_agent_context_ed25519(ctx_with_bad_hex, public_key)

        assert is_valid is False

    def test_rejects_non_string_signature(self, keypair, agent_ctx):
        """Test that non-string signature is rejected."""
        _, public_key = keypair

        ctx_with_wrong_type = AgentContext(
            agent_id="test-agent",
            version="1.0.0",
            owner="test-owner",
            metadata={"_ed25519_signature": 12345},
        )

        is_valid = verify_agent_context_ed25519(ctx_with_wrong_type, public_key)

        assert is_valid is False


class TestMakeEd25519Verifier:
    """Tests for make_ed25519_verifier."""

    def test_creates_verifier_function(self, keypair, agent_ctx):
        """Test that make_ed25519_verifier creates a working verifier."""
        private_key, public_key = keypair

        verifier = make_ed25519_verifier(public_key)
        signed_ctx = sign_agent_context_ed25519(agent_ctx, private_key)

        assert callable(verifier)
        assert verifier(signed_ctx) is True
        assert verifier(agent_ctx) is False  # Unsigned context

    def test_verifier_works_with_control_tower_pattern(self, keypair, agent_ctx):
        """Test that verifier works with the ControlTower.verify_fn pattern."""
        private_key, public_key = keypair

        # This simulates how verify_fn would be used
        verify_fn = make_ed25519_verifier(public_key)

        signed_ctx = sign_agent_context_ed25519(agent_ctx, private_key)

        # Simulate ControlTower calling verify_fn
        if verify_fn:
            result = verify_fn(signed_ctx)
            assert result is True


class TestCrossKeyVerification:
    """Tests for cross-key verification scenarios."""

    def test_multiple_agents_different_keys(self):
        """Test verifying multiple agents with different keys."""
        # Agent A
        private_a, public_a = generate_ed25519_keypair()
        ctx_a = AgentContext(agent_id="agent-a", version="1.0", owner="team-a")
        signed_a = sign_agent_context_ed25519(ctx_a, private_a)

        # Agent B
        private_b, public_b = generate_ed25519_keypair()
        ctx_b = AgentContext(agent_id="agent-b", version="1.0", owner="team-b")
        signed_b = sign_agent_context_ed25519(ctx_b, private_b)

        # Each agent's signature should verify with their own key
        assert verify_agent_context_ed25519(signed_a, public_a) is True
        assert verify_agent_context_ed25519(signed_b, public_b) is True

        # But not with the other's key
        assert verify_agent_context_ed25519(signed_a, public_b) is False
        assert verify_agent_context_ed25519(signed_b, public_a) is False

    def test_key_rotation_scenario(self):
        """Test a key rotation scenario."""
        # Old key
        old_private, old_public = generate_ed25519_keypair()
        # New key
        new_private, new_public = generate_ed25519_keypair()

        ctx = AgentContext(agent_id="agent", version="1.0", owner="owner")

        # Sign with old key
        signed_with_old = sign_agent_context_ed25519(ctx, old_private)

        # Verify with old key works
        assert verify_agent_context_ed25519(signed_with_old, old_public) is True

        # Verify with new key fails (as expected during rotation)
        assert verify_agent_context_ed25519(signed_with_old, new_public) is False

        # Re-sign with new key
        signed_with_new = sign_agent_context_ed25519(ctx, new_private)

        # Verify with new key works
        assert verify_agent_context_ed25519(signed_with_new, new_public) is True
