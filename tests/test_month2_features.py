"""Tests for Month 2 roadmap features (2.1, 2.2, 2.3, 2.6).

Covers:
  2.1 - Circuit Breaker Pattern
  2.2 - Cryptographic Manifest Signing (HMAC-SHA256)
  2.3 - Global URL Allowlisting (NetworkGuard)
  2.6 - Persistent Backends (SQLite GrantStore + ApprovalStore)
"""

import asyncio
import os
import tempfile
import time

import pytest

from tollgate import (
    AgentContext,
    ApprovalOutcome,
    AuditEvent,
    CircuitBreaker,
    CircuitState,
    ControlTower,
    Decision,
    DecisionType,
    Effect,
    Grant,
    InMemoryCircuitBreaker,
    Intent,
    NetworkGuard,
    Outcome,
    TollgateConstraintViolation,
    TollgateDenied,
    ToolRegistry,
    ToolRequest,
    get_manifest_hash,
    sign_manifest,
    verify_manifest,
)


# ─────────────────────────────────────────────────────────────────────
# Shared fixtures and mocks
# ─────────────────────────────────────────────────────────────────────


class MockPolicy:
    def __init__(self, decision_type: DecisionType = DecisionType.ALLOW):
        self.decision_type = decision_type

    def evaluate(self, _ctx, _intent, _req):
        return Decision(
            decision=self.decision_type,
            reason=f"Mock {self.decision_type.value}",
            policy_version="test",
        )


class MockApprover:
    async def request_approval_async(self, *_args):
        return ApprovalOutcome.APPROVED


class MockAudit:
    def __init__(self):
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent):
        self.events.append(event)


@pytest.fixture
def agent_ctx():
    return AgentContext(agent_id="test-agent", version="1.0", owner="test-owner")


@pytest.fixture
def intent():
    return Intent(action="test_action", reason="testing")


@pytest.fixture
def tool_req():
    return ToolRequest(
        tool="mock",
        action="run",
        resource_type="none",
        effect=Effect.READ,
        params={"x": 1},
    )


async def _noop_async():
    return "ok"


async def _failing_async():
    raise RuntimeError("tool execution failed")


# ─────────────────────────────────────────────────────────────────────
# 2.1 - Circuit Breaker Pattern
# ─────────────────────────────────────────────────────────────────────


class TestCircuitBreaker:
    """Tests for InMemoryCircuitBreaker standalone behavior."""

    @pytest.mark.asyncio
    async def test_starts_closed(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=3, cooldown_seconds=10)
        state = await breaker.get_state("tool", "action")
        assert state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_stays_closed_below_threshold(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=3, cooldown_seconds=10)

        # 2 failures (below threshold of 3)
        await breaker.record_failure("tool", "action")
        await breaker.record_failure("tool", "action")

        allowed, reason = await breaker.before_call("tool", "action")
        assert allowed is True
        assert reason is None
        assert await breaker.get_state("tool", "action") == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_opens_at_threshold(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=3, cooldown_seconds=60)

        for _ in range(3):
            await breaker.record_failure("tool", "action")

        assert await breaker.get_state("tool", "action") == CircuitState.OPEN
        allowed, reason = await breaker.before_call("tool", "action")
        assert allowed is False
        assert "Circuit OPEN" in reason

    @pytest.mark.asyncio
    async def test_open_transitions_to_half_open_after_cooldown(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=2, cooldown_seconds=0.1)

        await breaker.record_failure("tool", "action")
        await breaker.record_failure("tool", "action")
        assert await breaker.get_state("tool", "action") == CircuitState.OPEN

        # Wait for cooldown
        await asyncio.sleep(0.15)

        # Next call should be allowed (probe) and circuit goes to HALF_OPEN
        allowed, reason = await breaker.before_call("tool", "action")
        assert allowed is True
        assert await breaker.get_state("tool", "action") == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_half_open_success_closes_circuit(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=2, cooldown_seconds=0.05)

        await breaker.record_failure("tool", "action")
        await breaker.record_failure("tool", "action")
        await asyncio.sleep(0.1)

        # Probe call
        allowed, _ = await breaker.before_call("tool", "action")
        assert allowed is True
        assert await breaker.get_state("tool", "action") == CircuitState.HALF_OPEN

        # Probe succeeds
        await breaker.record_success("tool", "action")
        assert await breaker.get_state("tool", "action") == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_half_open_failure_reopens_circuit(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=2, cooldown_seconds=0.05)

        await breaker.record_failure("tool", "action")
        await breaker.record_failure("tool", "action")
        await asyncio.sleep(0.1)

        # Probe call
        allowed, _ = await breaker.before_call("tool", "action")
        assert allowed is True

        # Probe fails
        await breaker.record_failure("tool", "action")
        assert await breaker.get_state("tool", "action") == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_success_resets_failure_count(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=3, cooldown_seconds=60)

        await breaker.record_failure("tool", "action")
        await breaker.record_failure("tool", "action")
        await breaker.record_success("tool", "action")
        # Failure count should be reset
        await breaker.record_failure("tool", "action")
        await breaker.record_failure("tool", "action")

        # Only 2 failures since last success — should still be closed
        assert await breaker.get_state("tool", "action") == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_separate_circuits_per_tool_action(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=2, cooldown_seconds=60)

        await breaker.record_failure("tool_a", "action")
        await breaker.record_failure("tool_a", "action")
        assert await breaker.get_state("tool_a", "action") == CircuitState.OPEN

        # Different tool should be unaffected
        assert await breaker.get_state("tool_b", "action") == CircuitState.CLOSED
        allowed, _ = await breaker.before_call("tool_b", "action")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_reset_specific_circuit(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=2, cooldown_seconds=60)

        await breaker.record_failure("tool", "action")
        await breaker.record_failure("tool", "action")
        assert await breaker.get_state("tool", "action") == CircuitState.OPEN

        await breaker.reset("tool", "action")
        assert await breaker.get_state("tool", "action") == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_reset_all_circuits(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=1, cooldown_seconds=60)

        await breaker.record_failure("tool_a", "action")
        await breaker.record_failure("tool_b", "action")

        await breaker.reset()
        assert await breaker.get_state("tool_a", "action") == CircuitState.CLOSED
        assert await breaker.get_state("tool_b", "action") == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_get_all_states(self):
        breaker = InMemoryCircuitBreaker(failure_threshold=2, cooldown_seconds=60)

        await breaker.record_failure("tool_a", "action")
        await breaker.record_failure("tool_a", "action")
        await breaker.record_failure("tool_b", "run")

        states = await breaker.get_all_states()
        assert "tool_a:action" in states
        assert states["tool_a:action"]["state"] == "open"
        assert "tool_b:run" in states
        assert states["tool_b:run"]["state"] == "closed"

    def test_invalid_threshold(self):
        with pytest.raises(ValueError, match="failure_threshold"):
            InMemoryCircuitBreaker(failure_threshold=0)

    def test_invalid_cooldown(self):
        with pytest.raises(ValueError, match="cooldown_seconds"):
            InMemoryCircuitBreaker(cooldown_seconds=0)

    @pytest.mark.asyncio
    async def test_protocol_compliance(self):
        """InMemoryCircuitBreaker should satisfy the CircuitBreaker protocol."""
        breaker = InMemoryCircuitBreaker()
        assert isinstance(breaker, CircuitBreaker)


class TestCircuitBreakerTowerIntegration:
    """Tests for circuit breaker integration with ControlTower."""

    @pytest.mark.asyncio
    async def test_tower_blocks_when_circuit_open(self, agent_ctx, intent, tool_req):
        breaker = InMemoryCircuitBreaker(failure_threshold=2, cooldown_seconds=60)
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(), MockApprover(), audit, circuit_breaker=breaker,
        )

        # Open the circuit manually
        await breaker.record_failure(tool_req.tool, tool_req.action)
        await breaker.record_failure(tool_req.tool, tool_req.action)

        with pytest.raises(TollgateDenied, match="Circuit"):
            await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)

        blocked = [e for e in audit.events if e.outcome == Outcome.BLOCKED]
        assert len(blocked) == 1

    @pytest.mark.asyncio
    async def test_tower_records_failure_in_circuit_breaker(self, agent_ctx, intent, tool_req):
        breaker = InMemoryCircuitBreaker(failure_threshold=5, cooldown_seconds=60)
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(), MockApprover(), audit, circuit_breaker=breaker,
        )

        # Tool execution fails
        with pytest.raises(RuntimeError, match="tool execution failed"):
            await tower.execute_async(agent_ctx, intent, tool_req, _failing_async)

        # Breaker should have recorded the failure
        states = await breaker.get_all_states()
        key = f"{tool_req.tool}:{tool_req.action}"
        assert key in states
        assert states[key]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_tower_records_success_in_circuit_breaker(self, agent_ctx, intent, tool_req):
        breaker = InMemoryCircuitBreaker(failure_threshold=5, cooldown_seconds=60)
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(), MockApprover(), audit, circuit_breaker=breaker,
        )

        # Pre-record a failure
        await breaker.record_failure(tool_req.tool, tool_req.action)

        # Successful execution should reset the count
        await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)

        states = await breaker.get_all_states()
        key = f"{tool_req.tool}:{tool_req.action}"
        assert states[key]["failure_count"] == 0

    @pytest.mark.asyncio
    async def test_tower_circuit_open_after_n_failures(self, agent_ctx, intent, tool_req):
        breaker = InMemoryCircuitBreaker(failure_threshold=3, cooldown_seconds=60)
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(), MockApprover(), audit, circuit_breaker=breaker,
        )

        # Cause 3 failures through the tower
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await tower.execute_async(agent_ctx, intent, tool_req, _failing_async)

        # Next call should be blocked by circuit breaker
        with pytest.raises(TollgateDenied, match="Circuit"):
            await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)


# ─────────────────────────────────────────────────────────────────────
# 2.2 - Cryptographic Manifest Signing
# ─────────────────────────────────────────────────────────────────────


class TestManifestSigning:
    """Tests for HMAC-SHA256 manifest signing and verification."""

    def test_sign_creates_sig_file(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools: {}")

        sig_path = sign_manifest(manifest, secret_key=b"my-secret")
        assert sig_path.exists()
        assert sig_path.name == "manifest.yaml.sig"
        assert len(sig_path.read_text()) == 64  # SHA-256 hex digest

    def test_verify_valid_manifest(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools: {}")

        sign_manifest(manifest, secret_key=b"my-secret")
        assert verify_manifest(manifest, secret_key=b"my-secret") is True

    def test_verify_fails_wrong_key(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools: {}")

        sign_manifest(manifest, secret_key=b"correct-key")
        assert verify_manifest(manifest, secret_key=b"wrong-key") is False

    def test_verify_fails_tampered_manifest(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools: {}")

        sign_manifest(manifest, secret_key=b"my-secret")

        # Tamper with the manifest
        manifest.write_text("version: '1.0'\ntools:\n  evil_tool:\n    effect: write")

        assert verify_manifest(manifest, secret_key=b"my-secret") is False

    def test_verify_fails_missing_sig_file(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools: {}")

        # No .sig file created
        assert verify_manifest(manifest, secret_key=b"my-secret") is False

    def test_verify_fails_missing_manifest(self, tmp_path):
        assert verify_manifest(
            tmp_path / "nonexistent.yaml", secret_key=b"key"
        ) is False

    def test_sign_nonexistent_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            sign_manifest(tmp_path / "nope.yaml", secret_key=b"key")

    def test_get_manifest_hash(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools: {}")

        h = get_manifest_hash(manifest)
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

        # Same content → same hash
        h2 = get_manifest_hash(manifest)
        assert h == h2

    def test_different_content_different_hash(self, tmp_path):
        m1 = tmp_path / "m1.yaml"
        m2 = tmp_path / "m2.yaml"
        m1.write_text("version: '1.0'\ntools: {}")
        m2.write_text("version: '2.0'\ntools: {}")

        assert get_manifest_hash(m1) != get_manifest_hash(m2)


class TestManifestSigningRegistryIntegration:
    """Tests for ToolRegistry signature verification on load."""

    def test_registry_loads_with_valid_signature(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools:\n  'tool:a':\n    effect: read\n    resource_type: data")

        sign_manifest(manifest, secret_key=b"build-secret")

        # Should load without error
        registry = ToolRegistry(manifest, signing_key=b"build-secret")
        assert registry.version == "1.0"

    def test_registry_rejects_tampered_manifest(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools:\n  'tool:a':\n    effect: read\n    resource_type: data")

        sign_manifest(manifest, secret_key=b"build-secret")

        # Tamper
        manifest.write_text("version: '1.0'\ntools:\n  'tool:evil':\n    effect: write\n    resource_type: secret")

        with pytest.raises(ValueError, match="signature verification failed"):
            ToolRegistry(manifest, signing_key=b"build-secret")

    def test_registry_rejects_missing_signature(self, tmp_path):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools:\n  'tool:a':\n    effect: read\n    resource_type: data")

        # No signature file
        with pytest.raises(ValueError, match="signature verification failed"):
            ToolRegistry(manifest, signing_key=b"build-secret")

    def test_registry_loads_without_signing_key(self, tmp_path):
        """If no signing_key is provided, signature check is skipped."""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("version: '1.0'\ntools:\n  'tool:a':\n    effect: read\n    resource_type: data")

        registry = ToolRegistry(manifest)
        assert registry.version == "1.0"


# ─────────────────────────────────────────────────────────────────────
# 2.3 - Global URL Allowlisting (NetworkGuard)
# ─────────────────────────────────────────────────────────────────────


class TestNetworkGuard:
    """Tests for NetworkGuard standalone behavior."""

    def test_default_deny_blocks_all_urls(self):
        guard = NetworkGuard(default="deny")
        violations = guard.check({"url": "https://example.com/data"})
        assert len(violations) == 1
        assert "blocked" in violations[0].lower() or "not in" in violations[0].lower()

    def test_default_allow_permits_all_urls(self):
        guard = NetworkGuard(default="allow")
        violations = guard.check({"url": "https://anything.com/data"})
        assert violations == []

    def test_allowlist_permits_matching_urls(self):
        guard = NetworkGuard(
            default="deny",
            allowlist=[
                {"pattern": "https://api.github.com/*"},
                {"pattern": "https://arxiv.org/*"},
            ],
        )

        violations = guard.check({"url": "https://api.github.com/repos"})
        assert violations == []

        violations = guard.check({"url": "https://arxiv.org/abs/1234"})
        assert violations == []

    def test_allowlist_blocks_non_matching_urls(self):
        guard = NetworkGuard(
            default="deny",
            allowlist=[{"pattern": "https://api.github.com/*"}],
        )

        violations = guard.check({"url": "https://evil.com/steal"})
        assert len(violations) == 1
        assert "not in" in violations[0].lower() or "allowlist" in violations[0].lower()

    def test_blocklist_blocks_matching_urls(self):
        guard = NetworkGuard(
            default="allow",
            blocklist=[
                {"pattern": "http://*"},
                {"pattern": "*.internal.*"},
            ],
        )

        violations = guard.check({"url": "http://insecure.com/data"})
        assert len(violations) == 1
        assert "blocked" in violations[0].lower()

    def test_blocklist_wins_over_allowlist(self):
        guard = NetworkGuard(
            default="deny",
            allowlist=[{"pattern": "https://*"}],
            blocklist=[{"pattern": "https://evil.com/*"}],
        )

        # Allowed by allowlist but blocked by blocklist
        violations = guard.check({"url": "https://evil.com/steal"})
        assert len(violations) >= 1
        assert any("blocked" in v.lower() for v in violations)

    def test_param_fields_filter(self):
        guard = NetworkGuard(
            default="deny",
            allowlist=[{"pattern": "https://api.example.com/*"}],
            param_fields_to_check=["url", "endpoint"],
        )

        # 'url' is checked
        violations = guard.check({"url": "https://evil.com/x"})
        assert len(violations) > 0

        # 'other_field' is NOT checked (not in param_fields_to_check)
        violations = guard.check({"other_field": "https://evil.com/x"})
        assert violations == []

    def test_non_url_params_ignored(self):
        guard = NetworkGuard(default="deny")
        violations = guard.check({"name": "hello", "count": 42})
        assert violations == []

    def test_from_config(self):
        config = {
            "default": "deny",
            "allowlist": [
                {"pattern": "https://api.github.com/*"},
            ],
            "blocklist": [
                {"pattern": "http://*"},
            ],
            "param_fields_to_check": ["url"],
        }
        guard = NetworkGuard.from_config(config)

        # Allowed URL
        violations = guard.check({"url": "https://api.github.com/repos"})
        assert violations == []

        # Blocked URL
        violations = guard.check({"url": "http://insecure.com"})
        assert len(violations) >= 1

    def test_invalid_default_raises(self):
        with pytest.raises(ValueError, match="default must be"):
            NetworkGuard(default="maybe")

    def test_multiple_url_params(self):
        guard = NetworkGuard(
            default="deny",
            allowlist=[{"pattern": "https://safe.com/*"}],
        )

        violations = guard.check({
            "source": "https://safe.com/data",
            "target": "https://evil.com/exfil",
        })
        assert len(violations) == 1
        assert "target" in violations[0]


class TestNetworkGuardTowerIntegration:
    """Tests for NetworkGuard integration with ControlTower."""

    @pytest.mark.asyncio
    async def test_tower_blocks_network_policy_violation(self, agent_ctx, intent):
        guard = NetworkGuard(
            default="deny",
            allowlist=[{"pattern": "https://api.github.com/*"}],
        )
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(), MockApprover(), audit, network_guard=guard,
        )

        tool_req = ToolRequest(
            tool="fetch",
            action="get",
            resource_type="url",
            effect=Effect.READ,
            params={"url": "https://evil.com/steal"},
        )

        with pytest.raises(TollgateConstraintViolation, match="Network policy violation"):
            await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)

        blocked = [e for e in audit.events if e.outcome == Outcome.BLOCKED]
        assert len(blocked) == 1

    @pytest.mark.asyncio
    async def test_tower_allows_network_policy_compliant(self, agent_ctx, intent):
        guard = NetworkGuard(
            default="deny",
            allowlist=[{"pattern": "https://api.github.com/*"}],
        )
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(), MockApprover(), audit, network_guard=guard,
        )

        tool_req = ToolRequest(
            tool="fetch",
            action="get",
            resource_type="url",
            effect=Effect.READ,
            params={"url": "https://api.github.com/repos"},
        )

        result = await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_network_guard_skipped_when_policy_denies(self, agent_ctx, intent):
        """NetworkGuard should not run if policy already denied."""
        guard = NetworkGuard(
            default="deny",
            allowlist=[],  # Block everything
        )
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(DecisionType.DENY), MockApprover(), audit,
            network_guard=guard,
        )

        tool_req = ToolRequest(
            tool="fetch",
            action="get",
            resource_type="url",
            effect=Effect.READ,
            params={"url": "https://evil.com/steal"},
        )

        with pytest.raises(TollgateDenied):
            await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)


# ─────────────────────────────────────────────────────────────────────
# 2.6 - Persistent Backends (SQLite)
# ─────────────────────────────────────────────────────────────────────


class TestSQLiteGrantStore:
    """Tests for SQLiteGrantStore."""

    @pytest.fixture
    def store(self, tmp_path):
        from tollgate.backends import SQLiteGrantStore
        db = tmp_path / "grants.db"
        return SQLiteGrantStore(str(db))

    @pytest.fixture
    def sample_grant(self):
        return Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="api:fetch",
            action="get",
            resource_type="url",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            reason="testing",
        )

    @pytest.mark.asyncio
    async def test_create_and_find_grant(self, store, sample_grant, agent_ctx):
        grant_id = await store.create_grant(sample_grant)
        assert grant_id == sample_grant.id

        tool_req = ToolRequest(
            tool="api:fetch",
            action="get",
            resource_type="url",
            effect=Effect.READ,
            params={},
        )
        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="test")
        found = await store.find_matching_grant(ctx, tool_req)
        assert found is not None
        assert found.id == sample_grant.id

    @pytest.mark.asyncio
    async def test_find_returns_none_no_match(self, store, sample_grant, agent_ctx):
        await store.create_grant(sample_grant)

        tool_req = ToolRequest(
            tool="other:tool",
            action="delete",
            resource_type="file",
            effect=Effect.DELETE,
            params={},
        )
        found = await store.find_matching_grant(agent_ctx, tool_req)
        assert found is None

    @pytest.mark.asyncio
    async def test_expired_grant_not_found(self, store):
        expired_grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="api:fetch",
            action="get",
            resource_type="url",
            expires_at=time.time() - 10,  # Already expired
            granted_by="admin",
            created_at=time.time() - 100,
        )
        await store.create_grant(expired_grant)

        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="test")
        tool_req = ToolRequest("api:fetch", "get", "url", Effect.READ, {})
        found = await store.find_matching_grant(ctx, tool_req)
        assert found is None

    @pytest.mark.asyncio
    async def test_revoke_grant(self, store, sample_grant):
        await store.create_grant(sample_grant)

        success = await store.revoke_grant(sample_grant.id)
        assert success is True

        # Cannot find revoked grant
        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="test")
        tool_req = ToolRequest("api:fetch", "get", "url", Effect.READ, {})
        found = await store.find_matching_grant(ctx, tool_req)
        assert found is None

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_returns_false(self, store):
        result = await store.revoke_grant("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_list_active_grants(self, store, sample_grant):
        await store.create_grant(sample_grant)

        # Add an expired grant
        expired = Grant(
            agent_id="agent-1",
            effect=Effect.WRITE,
            tool="db:write",
            action="insert",
            resource_type="database",
            expires_at=time.time() - 10,
            granted_by="admin",
            created_at=time.time() - 100,
        )
        await store.create_grant(expired)

        active = await store.list_active_grants()
        assert len(active) == 1
        assert active[0].id == sample_grant.id

    @pytest.mark.asyncio
    async def test_list_active_by_agent(self, store):
        g1 = Grant(
            agent_id="agent-1", effect=Effect.READ, tool=None, action=None,
            resource_type=None, expires_at=time.time() + 3600,
            granted_by="admin", created_at=time.time(),
        )
        g2 = Grant(
            agent_id="agent-2", effect=Effect.WRITE, tool=None, action=None,
            resource_type=None, expires_at=time.time() + 3600,
            granted_by="admin", created_at=time.time(),
        )
        await store.create_grant(g1)
        await store.create_grant(g2)

        agent1_grants = await store.list_active_grants("agent-1")
        assert len(agent1_grants) == 1
        assert agent1_grants[0].agent_id == "agent-1"

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, store):
        expired = Grant(
            agent_id="agent-1", effect=Effect.READ, tool=None, action=None,
            resource_type=None, expires_at=time.time() - 10,
            granted_by="admin", created_at=time.time() - 100,
        )
        active = Grant(
            agent_id="agent-1", effect=Effect.READ, tool=None, action=None,
            resource_type=None, expires_at=time.time() + 3600,
            granted_by="admin", created_at=time.time(),
        )
        await store.create_grant(expired)
        await store.create_grant(active)

        removed = await store.cleanup_expired()
        assert removed == 1

        all_active = await store.list_active_grants()
        assert len(all_active) == 1

    @pytest.mark.asyncio
    async def test_usage_count(self, store, sample_grant, agent_ctx):
        await store.create_grant(sample_grant)

        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="test")
        tool_req = ToolRequest("api:fetch", "get", "url", Effect.READ, {})

        # Find grants 3 times
        for _ in range(3):
            await store.find_matching_grant(ctx, tool_req)

        count = await store.get_usage_count(sample_grant.id)
        assert count == 3

    @pytest.mark.asyncio
    async def test_prefix_tool_matching(self, store):
        grant = Grant(
            agent_id="agent-1", effect=None, tool="mcp:*", action=None,
            resource_type=None, expires_at=time.time() + 3600,
            granted_by="admin", created_at=time.time(),
        )
        await store.create_grant(grant)

        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="test")
        tool_req = ToolRequest("mcp:server.tool", "run", "data", Effect.READ, {})

        found = await store.find_matching_grant(ctx, tool_req)
        assert found is not None

        # Non-matching prefix
        tool_req2 = ToolRequest("langchain:tool", "run", "data", Effect.READ, {})
        found2 = await store.find_matching_grant(ctx, tool_req2)
        assert found2 is None

    @pytest.mark.asyncio
    async def test_memory_mode(self):
        """Test with :memory: database for ephemeral testing."""
        from tollgate.backends import SQLiteGrantStore
        store = SQLiteGrantStore(":memory:")

        grant = Grant(
            agent_id="agent-1", effect=Effect.READ, tool="t", action="a",
            resource_type="r", expires_at=time.time() + 3600,
            granted_by="admin", created_at=time.time(),
        )
        grant_id = await store.create_grant(grant)
        assert grant_id == grant.id


class TestSQLiteApprovalStore:
    """Tests for SQLiteApprovalStore."""

    @pytest.fixture
    def store(self, tmp_path):
        from tollgate.backends import SQLiteApprovalStore
        db = tmp_path / "approvals.db"
        return SQLiteApprovalStore(str(db), poll_interval=0.05)

    @pytest.fixture
    def agent_ctx(self):
        return AgentContext(agent_id="agent-1", version="1.0", owner="test")

    @pytest.fixture
    def intent(self):
        return Intent(action="test", reason="testing")

    @pytest.fixture
    def tool_req(self):
        return ToolRequest("tool:a", "run", "data", Effect.READ, {})

    @pytest.mark.asyncio
    async def test_create_and_get_request(self, store, agent_ctx, intent, tool_req):
        approval_id = await store.create_request(
            agent_ctx, intent, tool_req, "hash123", "needs approval", time.time() + 3600
        )
        assert approval_id is not None

        req = await store.get_request(approval_id)
        assert req is not None
        assert req["id"] == approval_id
        assert req["request_hash"] == "hash123"
        assert req["reason"] == "needs approval"
        assert req["outcome"] == ApprovalOutcome.DEFERRED

    @pytest.mark.asyncio
    async def test_set_decision(self, store, agent_ctx, intent, tool_req):
        approval_id = await store.create_request(
            agent_ctx, intent, tool_req, "hash123", "reason", time.time() + 3600
        )

        await store.set_decision(
            approval_id, ApprovalOutcome.APPROVED, "admin", time.time(), "hash123"
        )

        req = await store.get_request(approval_id)
        assert req["outcome"] == ApprovalOutcome.APPROVED

    @pytest.mark.asyncio
    async def test_set_decision_hash_mismatch(self, store, agent_ctx, intent, tool_req):
        approval_id = await store.create_request(
            agent_ctx, intent, tool_req, "hash123", "reason", time.time() + 3600
        )

        with pytest.raises(ValueError, match="hash mismatch"):
            await store.set_decision(
                approval_id, ApprovalOutcome.APPROVED, "admin", time.time(), "wrong-hash"
            )

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, store):
        req = await store.get_request("nonexistent-id")
        assert req is None

    @pytest.mark.asyncio
    async def test_wait_for_decision_immediate(self, store, agent_ctx, intent, tool_req):
        """Decision is set before wait — should return immediately."""
        approval_id = await store.create_request(
            agent_ctx, intent, tool_req, "hash123", "reason", time.time() + 3600
        )

        await store.set_decision(
            approval_id, ApprovalOutcome.APPROVED, "admin", time.time(), "hash123"
        )

        outcome = await store.wait_for_decision(approval_id, timeout=1.0)
        assert outcome == ApprovalOutcome.APPROVED

    @pytest.mark.asyncio
    async def test_wait_for_decision_timeout(self, store, agent_ctx, intent, tool_req):
        """No decision set — should timeout."""
        approval_id = await store.create_request(
            agent_ctx, intent, tool_req, "hash123", "reason", time.time() + 3600
        )

        outcome = await store.wait_for_decision(approval_id, timeout=0.2)
        assert outcome == ApprovalOutcome.TIMEOUT

    @pytest.mark.asyncio
    async def test_wait_for_decision_async_set(self, store, agent_ctx, intent, tool_req):
        """Decision set asynchronously while waiting."""
        approval_id = await store.create_request(
            agent_ctx, intent, tool_req, "hash123", "reason", time.time() + 3600
        )

        async def set_decision_later():
            await asyncio.sleep(0.1)
            await store.set_decision(
                approval_id, ApprovalOutcome.DENIED, "admin", time.time(), "hash123"
            )

        # Start setter and waiter concurrently
        task = asyncio.create_task(set_decision_later())
        outcome = await store.wait_for_decision(approval_id, timeout=2.0)
        await task

        assert outcome == ApprovalOutcome.DENIED

    @pytest.mark.asyncio
    async def test_wait_expired_request_returns_timeout(self, store, agent_ctx, intent, tool_req):
        """Expired request should return TIMEOUT."""
        approval_id = await store.create_request(
            agent_ctx, intent, tool_req, "hash123", "reason",
            time.time() - 1  # Already expired
        )

        outcome = await store.wait_for_decision(approval_id, timeout=0.5)
        assert outcome == ApprovalOutcome.TIMEOUT


# ─────────────────────────────────────────────────────────────────────
# Integration: Month 2 features combined
# ─────────────────────────────────────────────────────────────────────


class TestMonth2Integration:
    """Integration tests combining multiple Month 2 features."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_plus_network_guard(self, agent_ctx, intent):
        """Circuit breaker and network guard work together."""
        breaker = InMemoryCircuitBreaker(failure_threshold=5, cooldown_seconds=60)
        guard = NetworkGuard(
            default="deny",
            allowlist=[{"pattern": "https://api.safe.com/*"}],
        )
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(), MockApprover(), audit,
            circuit_breaker=breaker,
            network_guard=guard,
        )

        # Allowed URL
        good_req = ToolRequest(
            tool="fetch", action="get", resource_type="url",
            effect=Effect.READ, params={"url": "https://api.safe.com/data"},
        )
        result = await tower.execute_async(agent_ctx, intent, good_req, _noop_async)
        assert result == "ok"

        # Blocked URL by network guard
        bad_req = ToolRequest(
            tool="fetch", action="get", resource_type="url",
            effect=Effect.READ, params={"url": "https://evil.com/steal"},
        )
        with pytest.raises(TollgateConstraintViolation, match="Network policy"):
            await tower.execute_async(agent_ctx, intent, bad_req, _noop_async)

    @pytest.mark.asyncio
    async def test_signed_manifest_with_network_guard(self, tmp_path, agent_ctx, intent):
        """Signed manifest + network guard for defense-in-depth."""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("""
version: "1.0.0"
tools:
  "api:fetch":
    effect: read
    resource_type: url
    constraints:
      allowed_url_patterns:
        - "https://api.github.com/*"
""")
        sign_manifest(manifest, secret_key=b"build-secret")

        registry = ToolRegistry(manifest, signing_key=b"build-secret")
        guard = NetworkGuard(
            default="deny",
            allowlist=[
                {"pattern": "https://api.github.com/*"},
                {"pattern": "https://api.safe.com/*"},
            ],
        )
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(), MockApprover(), audit,
            registry=registry,
            network_guard=guard,
        )

        # URL allowed by both manifest constraints AND network guard
        good_req = ToolRequest(
            tool="api:fetch", action="get", resource_type="url",
            effect=Effect.READ, params={"url": "https://api.github.com/repos"},
            manifest_version="1.0.0",
        )
        result = await tower.execute_async(agent_ctx, intent, good_req, _noop_async)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_sqlite_store_with_tower(self, tmp_path, intent):
        """SQLite grant store works with ControlTower for ASK decisions."""
        from tollgate.backends import SQLiteGrantStore

        store = SQLiteGrantStore(str(tmp_path / "grants.db"))
        audit = MockAudit()

        # Pre-create a grant
        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="api:fetch",
            action=None,
            resource_type=None,
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
        )
        await store.create_grant(grant)

        tower = ControlTower(
            MockPolicy(DecisionType.ASK),
            MockApprover(),
            audit,
            grant_store=store,
        )

        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="test")
        tool_req = ToolRequest(
            tool="api:fetch", action="get", resource_type="url",
            effect=Effect.READ, params={},
        )

        # Should match the grant and skip approval
        result = await tower.execute_async(ctx, intent, tool_req, _noop_async)
        assert result == "ok"
        assert audit.events[-1].outcome == Outcome.EXECUTED
