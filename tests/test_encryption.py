"""Tests for field-level encryption and encrypted audit sink.

These tests require the cryptography package. They are skipped if
cryptography is not available.
"""

import os

import pytest

cryptography = pytest.importorskip("cryptography")

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
from tollgate.security.encryption import (
    EncryptedAuditSink,
    EncryptedValue,
    EncryptedValueDecoder,
    FieldEncryptor,
)


@pytest.fixture
def encryption_key():
    """Generate a valid 32-byte encryption key."""
    return os.urandom(32)


@pytest.fixture
def encryptor(encryption_key):
    """Create a FieldEncryptor instance."""
    return FieldEncryptor(encryption_key, key_id="test-key-v1")


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
            action="fetch_data",
            reason="User requested data",
        ),
        tool_request=ToolRequest(
            tool="api:fetch",
            action="get",
            resource_type="url",
            effect=Effect.READ,
            params={"url": "https://example.com", "api_key": "secret123"},
        ),
        decision=Decision(
            decision=DecisionType.ALLOW,
            reason="Test allow",
        ),
        outcome=Outcome.EXECUTED,
    )


class TestFieldEncryptor:
    """Tests for FieldEncryptor."""

    def test_init_with_valid_key(self, encryption_key):
        """Test initialization with valid 32-byte key."""
        encryptor = FieldEncryptor(encryption_key, key_id="my-key")
        assert encryptor is not None

    def test_init_with_invalid_key_length(self):
        """Test that invalid key length raises error."""
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            FieldEncryptor(b"short", key_id="my-key")

        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            FieldEncryptor(b"x" * 64, key_id="my-key")

    def test_encrypt_returns_encrypted_value(self, encryptor):
        """Test that encrypt returns an EncryptedValue."""
        plaintext = "sensitive data"
        encrypted = encryptor.encrypt(plaintext)

        assert isinstance(encrypted, EncryptedValue)
        assert encrypted.key_id == "test-key-v1"
        assert isinstance(encrypted.nonce, str)
        assert isinstance(encrypted.ciphertext, str)
        # Base64 encoded 12 bytes is 16 chars
        assert len(encrypted.nonce) == 16

    def test_decrypt_returns_original(self, encryptor):
        """Test that decrypt returns the original plaintext."""
        plaintext = "sensitive data"
        encrypted = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(encrypted)

        assert decrypted == plaintext

    def test_encrypt_different_nonces(self, encryptor):
        """Test that each encryption uses a unique nonce."""
        plaintext = "same data"
        encrypted1 = encryptor.encrypt(plaintext)
        encrypted2 = encryptor.encrypt(plaintext)

        assert encrypted1.nonce != encrypted2.nonce
        assert encrypted1.ciphertext != encrypted2.ciphertext

    def test_decrypt_with_wrong_key_fails(self, encryption_key):
        """Test that decryption fails with wrong key."""
        encryptor1 = FieldEncryptor(encryption_key, key_id="key1")
        other_key = os.urandom(32)
        encryptor2 = FieldEncryptor(other_key, key_id="key1")  # Same key_id but different key

        encrypted = encryptor1.encrypt("secret")

        with pytest.raises(ValueError, match="Decryption failed"):
            encryptor2.decrypt(encrypted)

    def test_encrypted_value_to_dict(self, encryptor):
        """Test that EncryptedValue converts to dict."""
        encrypted = encryptor.encrypt("data")
        d = encrypted.to_dict()

        assert d["_encrypted"] is True
        assert d["key_id"] == "test-key-v1"
        assert "nonce" in d
        assert "ciphertext" in d

    def test_encrypted_value_from_dict(self, encryptor):
        """Test that EncryptedValue can be created from dict."""
        encrypted = encryptor.encrypt("data")
        d = encrypted.to_dict()

        restored = EncryptedValue.from_dict(d)

        assert restored.key_id == encrypted.key_id
        assert restored.nonce == encrypted.nonce
        assert restored.ciphertext == encrypted.ciphertext

    def test_encrypted_value_roundtrip(self, encryptor):
        """Test full roundtrip: encrypt -> dict -> restore -> decrypt."""
        plaintext = "important secret"

        encrypted = encryptor.encrypt(plaintext)
        d = encrypted.to_dict()
        restored = EncryptedValue.from_dict(d)
        decrypted = encryptor.decrypt(restored)

        assert decrypted == plaintext

    def test_encrypt_unicode(self, encryptor):
        """Test encryption of unicode strings."""
        plaintext = "Hello 世界 🌍 émoji"
        encrypted = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(encrypted)

        assert decrypted == plaintext

    def test_encrypt_empty_string(self, encryptor):
        """Test encryption of empty string."""
        encrypted = encryptor.encrypt("")
        decrypted = encryptor.decrypt(encrypted)

        assert decrypted == ""

    def test_encrypt_large_data(self, encryptor):
        """Test encryption of large data."""
        plaintext = "x" * 100000  # 100KB
        encrypted = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(encrypted)

        assert decrypted == plaintext

    def test_encrypt_dict(self, encryptor):
        """Test encrypting a dictionary."""
        data = {"key": "value", "number": 42}
        encrypted = encryptor.encrypt_dict(data)

        assert encrypted["_encrypted"] is True
        assert "ciphertext" in encrypted

    def test_decrypt_dict(self, encryptor):
        """Test decrypting a dictionary."""
        data = {"key": "value", "number": 42}
        encrypted = encryptor.encrypt_dict(data)
        decrypted = encryptor.decrypt_dict(encrypted)

        assert decrypted == data


class TestEncryptedValue:
    """Tests for EncryptedValue class."""

    def test_is_encrypted_true(self):
        """Test is_encrypted returns True for encrypted dicts."""
        data = {"_encrypted": True, "ciphertext": "...", "nonce": "..."}
        assert EncryptedValue.is_encrypted(data) is True

    def test_is_encrypted_false_no_marker(self):
        """Test is_encrypted returns False without marker."""
        data = {"ciphertext": "...", "nonce": "..."}
        assert EncryptedValue.is_encrypted(data) is False

    def test_is_encrypted_false_not_dict(self):
        """Test is_encrypted returns False for non-dicts."""
        assert EncryptedValue.is_encrypted("string") is False
        assert EncryptedValue.is_encrypted(123) is False
        assert EncryptedValue.is_encrypted(None) is False


class TestEncryptedValueDecoder:
    """Tests for EncryptedValueDecoder."""

    def test_decrypt_event(self, encryptor):
        """Test decrypting an event with encrypted values."""
        encrypted = encryptor.encrypt_dict({"secret": "value"})

        event = {
            "normal": "visible",
            "secret_data": encrypted,
        }

        decoder = EncryptedValueDecoder({encryptor.key_id: encryptor})
        decrypted = decoder.decrypt_event(event)

        assert decrypted["normal"] == "visible"
        assert decrypted["secret_data"] == {"secret": "value"}

    def test_decrypt_nested(self, encryptor):
        """Test decrypting nested encrypted values."""
        inner_encrypted = encryptor.encrypt_dict({"deep": "secret"})

        event = {
            "level1": {
                "level2": inner_encrypted,
            }
        }

        decoder = EncryptedValueDecoder({encryptor.key_id: encryptor})
        decrypted = decoder.decrypt_event(event)

        assert decrypted["level1"]["level2"] == {"deep": "secret"}

    def test_decrypt_missing_key_raises(self, encryptor):
        """Test that missing key raises error."""
        encrypted = encryptor.encrypt_dict({"data": "value"})

        decoder = EncryptedValueDecoder({})  # No encryptors

        with pytest.raises(ValueError, match="No encryptor for key_id"):
            decoder.decrypt_event({"data": encrypted})


class TestEncryptedAuditSink:
    """Tests for EncryptedAuditSink."""

    def test_encrypts_params(self, encryptor, sample_audit_event):
        """Test that params field is encrypted."""
        events = []

        class MockSink:
            def emit(self, event):
                events.append(event.to_dict())

        sink = EncryptedAuditSink(MockSink(), encryptor)
        sink.emit(sample_audit_event)

        assert len(events) == 1
        event = events[0]

        # params should be encrypted
        params = event["tool_request"]["params"]
        assert params.get("_encrypted") is True
        assert "ciphertext" in params

    def test_preserves_non_sensitive_fields(self, encryptor, sample_audit_event):
        """Test that non-sensitive fields are preserved."""
        events = []

        class MockSink:
            def emit(self, event):
                events.append(event.to_dict())

        sink = EncryptedAuditSink(MockSink(), encryptor)
        sink.emit(sample_audit_event)

        event = events[0]

        # Non-sensitive fields should be unchanged
        assert event["agent"]["agent_id"] == "test-agent"
        assert event["tool_request"]["tool"] == "api:fetch"
        assert event["decision"]["decision"] == "ALLOW"

    def test_can_decrypt_params(self, encryptor, sample_audit_event):
        """Test that encrypted params can be decrypted."""
        events = []

        class MockSink:
            def emit(self, event):
                events.append(event.to_dict())

        sink = EncryptedAuditSink(MockSink(), encryptor)
        sink.emit(sample_audit_event)

        event = events[0]

        # Decrypt the params
        encrypted_params = event["tool_request"]["params"]
        decrypted = encryptor.decrypt_dict(encrypted_params)

        assert decrypted["url"] == "https://example.com"
        assert decrypted["api_key"] == "secret123"

    def test_custom_sensitive_fields(self, encryptor):
        """Test custom list of sensitive fields."""
        events = []

        class MockSink:
            def emit(self, event):
                events.append(event.to_dict())

        # Create event with empty params to avoid default encryption
        event = AuditEvent(
            schema_version="1.0",
            timestamp="2024-01-15T10:00:00Z",
            correlation_id="test-123",
            request_hash="hash123",
            agent=AgentContext(agent_id="test", version="1.0", owner="owner"),
            intent=Intent(action="test", reason="testing"),
            tool_request=ToolRequest(
                tool="test",
                action="act",
                resource_type="res",
                effect=Effect.READ,
                params={},  # Empty params
            ),
            decision=Decision(decision=DecisionType.ALLOW, reason="ok"),
            outcome=Outcome.EXECUTED,
            result_summary="sensitive result data",
        )

        # Only encrypt result_summary
        sink = EncryptedAuditSink(
            MockSink(),
            encryptor,
            sensitive_fields=frozenset({"result_summary"}),
        )
        sink.emit(event)

        emitted = events[0]

        # result_summary should be encrypted
        assert emitted["result_summary"]["_encrypted"] is True

        # params should NOT be encrypted (not in custom list)
        assert "_encrypted" not in emitted["tool_request"]["params"]

    def test_handles_empty_params(self, encryptor):
        """Test handling of empty params."""
        events = []

        class MockSink:
            def emit(self, event):
                events.append(event.to_dict())

        event = AuditEvent(
            schema_version="1.0",
            timestamp="2024-01-15T10:00:00Z",
            correlation_id="test-123",
            request_hash="abc",
            agent=AgentContext(agent_id="test", version="1.0", owner="owner"),
            intent=Intent(action="test", reason="testing"),
            tool_request=ToolRequest(
                tool="test",
                action="act",
                resource_type="res",
                effect=Effect.READ,
                params={},  # Empty params
            ),
            decision=Decision(decision=DecisionType.ALLOW, reason="ok"),
            outcome=Outcome.EXECUTED,
        )

        sink = EncryptedAuditSink(MockSink(), encryptor)
        sink.emit(event)  # Should not raise

        assert len(events) == 1

    def test_key_id_in_encrypted_output(self, encryptor, sample_audit_event):
        """Test that key_id is included in encrypted output."""
        events = []

        class MockSink:
            def emit(self, event):
                events.append(event.to_dict())

        sink = EncryptedAuditSink(MockSink(), encryptor)
        sink.emit(sample_audit_event)

        event = events[0]

        # Check key_id is present
        assert event["tool_request"]["params"]["key_id"] == "test-key-v1"
