"""Tests for Month 1 roadmap features (1.1 through 1.6).

Covers:
  1.1 - Parameter Schema Validation
  1.2 - Rate Limiting
  1.3 - Audit Schema Versioning
  1.4 - READ Gating / Constraints
  1.5 - WebhookAuditSink + CompositeAuditSink
  1.6 - Agent Identity HMAC Signing
"""

import time

import pytest

from tollgate import (
    AgentContext,
    ApprovalOutcome,
    AuditEvent,
    CompositeAuditSink,
    ControlTower,
    Decision,
    DecisionType,
    Effect,
    InMemoryRateLimiter,
    Intent,
    Outcome,
    TollgateConstraintViolation,
    TollgateDenied,
    TollgateRateLimited,
    ToolRegistry,
    ToolRequest,
    WebhookAuditSink,
    make_verifier,
    sign_agent_context,
    verify_agent_context,
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
        manifest_version="1.0.0",
    )


# ─────────────────────────────────────────────────────────────────────
# 1.3 - Audit Schema Versioning
# ─────────────────────────────────────────────────────────────────────


class TestAuditSchemaVersioning:
    def test_audit_event_has_schema_version(self, agent_ctx, intent, tool_req):
        audit = MockAudit()
        tower = ControlTower(MockPolicy(), MockApprover(), audit)
        tower.execute(agent_ctx, intent, tool_req, lambda: "ok")

        assert len(audit.events) == 1
        assert audit.events[0].schema_version == "1.0"

    def test_audit_event_to_dict_includes_schema_version(self, agent_ctx, intent, tool_req):
        audit = MockAudit()
        tower = ControlTower(MockPolicy(), MockApprover(), audit)
        tower.execute(agent_ctx, intent, tool_req, lambda: "ok")

        event_dict = audit.events[0].to_dict()
        assert "schema_version" in event_dict
        assert event_dict["schema_version"] == "1.0"

    def test_schema_version_is_first_key_in_dict(self, agent_ctx, intent, tool_req):
        audit = MockAudit()
        tower = ControlTower(MockPolicy(), MockApprover(), audit)
        tower.execute(agent_ctx, intent, tool_req, lambda: "ok")

        event_dict = audit.events[0].to_dict()
        first_key = list(event_dict.keys())[0]
        assert first_key == "schema_version"


# ─────────────────────────────────────────────────────────────────────
# 1.5 - CompositeAuditSink + WebhookAuditSink
# ─────────────────────────────────────────────────────────────────────


class TestCompositeAuditSink:
    def test_composite_emits_to_all_sinks(self, agent_ctx, intent, tool_req):
        sink1 = MockAudit()
        sink2 = MockAudit()
        composite = CompositeAuditSink([sink1, sink2])

        tower = ControlTower(MockPolicy(), MockApprover(), composite)
        tower.execute(agent_ctx, intent, tool_req, lambda: "ok")

        assert len(sink1.events) == 1
        assert len(sink2.events) == 1

    def test_composite_survives_sink_failure(self, agent_ctx, intent, tool_req):
        class FailingSink:
            def emit(self, event):
                raise RuntimeError("Sink failed!")

        good_sink = MockAudit()
        composite = CompositeAuditSink([FailingSink(), good_sink])

        tower = ControlTower(MockPolicy(), MockApprover(), composite)
        tower.execute(agent_ctx, intent, tool_req, lambda: "ok")

        # Good sink still received the event despite the failing one
        assert len(good_sink.events) == 1

    def test_composite_requires_at_least_one_sink(self):
        with pytest.raises(ValueError, match="at least one sink"):
            CompositeAuditSink([])


class TestWebhookAuditSink:
    def test_webhook_init_requires_url(self):
        with pytest.raises(ValueError, match="must not be empty"):
            WebhookAuditSink("")

    def test_webhook_skips_non_alert_outcomes(self, agent_ctx, intent, tool_req):
        """EXECUTED outcome should not trigger a webhook."""
        # We can't easily test HTTP calls without a server, but we can
        # verify the sink doesn't raise for non-alert events.
        sink = WebhookAuditSink("https://example.com/hook")

        audit = MockAudit()
        tower = ControlTower(MockPolicy(), MockApprover(), audit)
        tower.execute(agent_ctx, intent, tool_req, lambda: "ok")

        event = audit.events[0]
        assert event.outcome == Outcome.EXECUTED
        # Calling emit directly should be a no-op (no HTTP call)
        sink.emit(event)  # Should not raise

    def test_webhook_fires_for_blocked_outcomes(self, agent_ctx, intent, tool_req):
        """BLOCKED outcome should trigger webhook logic."""
        sink = WebhookAuditSink("https://example.com/hook")

        audit = MockAudit()
        tower = ControlTower(MockPolicy(DecisionType.DENY), MockApprover(), audit)

        with pytest.raises(TollgateDenied):
            tower.execute(agent_ctx, intent, tool_req, lambda: "ok")

        event = audit.events[0]
        assert event.outcome == Outcome.BLOCKED
        # The webhook will attempt delivery on a daemon thread.
        # It will fail (no server) but should not raise in emit().
        sink.emit(event)

    def test_webhook_custom_alert_outcomes(self):
        sink = WebhookAuditSink(
            "https://example.com/hook",
            alert_outcomes=frozenset({Outcome.FAILED}),
        )
        assert Outcome.BLOCKED not in sink.alert_outcomes
        assert Outcome.FAILED in sink.alert_outcomes


# ─────────────────────────────────────────────────────────────────────
# 1.1 - Parameter Schema Validation
# ─────────────────────────────────────────────────────────────────────


class TestParameterSchemaValidation:
    def _make_registry(self, tmp_path, tools_yaml):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(f'version: "1.0.0"\ntools:\n{tools_yaml}')
        return ToolRegistry(manifest)

    def test_no_schema_means_no_errors(self, tmp_path):
        registry = self._make_registry(tmp_path, '  "tool:a":\n    effect: "read"\n    resource_type: "data"')
        errors = registry.validate_params("tool:a", {"anything": "goes"})
        assert errors == []

    def test_required_fields_validated(self, tmp_path):
        yaml_text = """  "tool:write":
    effect: "write"
    resource_type: "file"
    params_schema:
      type: object
      required:
        - path
        - content
      properties:
        path:
          type: string
        content:
          type: string"""
        registry = self._make_registry(tmp_path, yaml_text)

        # Missing both required fields
        errors = registry.validate_params("tool:write", {})
        assert len(errors) == 2
        assert any("path" in e for e in errors)
        assert any("content" in e for e in errors)

        # Valid
        errors = registry.validate_params("tool:write", {"path": "/tmp/x", "content": "hello"})
        assert errors == []

    def test_type_validation(self, tmp_path):
        yaml_text = """  "tool:typed":
    effect: "read"
    resource_type: "data"
    params_schema:
      type: object
      properties:
        count:
          type: integer
        name:
          type: string"""
        registry = self._make_registry(tmp_path, yaml_text)

        errors = registry.validate_params("tool:typed", {"count": "not_a_number"})
        assert len(errors) == 1
        assert "integer" in errors[0]

        errors = registry.validate_params("tool:typed", {"count": 5, "name": "ok"})
        assert errors == []

    def test_string_pattern_validation(self, tmp_path):
        yaml_text = """  "tool:path":
    effect: "write"
    resource_type: "file"
    params_schema:
      type: object
      properties:
        path:
          type: string
          pattern: "^/safe/"
          maxLength: 100"""
        registry = self._make_registry(tmp_path, yaml_text)

        errors = registry.validate_params("tool:path", {"path": "/unsafe/file.txt"})
        assert len(errors) == 1
        assert "pattern" in errors[0]

        errors = registry.validate_params("tool:path", {"path": "/safe/file.txt"})
        assert errors == []

    def test_numeric_range_validation(self, tmp_path):
        yaml_text = """  "tool:range":
    effect: "write"
    resource_type: "data"
    params_schema:
      type: object
      properties:
        count:
          type: integer
          minimum: 1
          maximum: 100"""
        registry = self._make_registry(tmp_path, yaml_text)

        errors = registry.validate_params("tool:range", {"count": 0})
        assert len(errors) == 1
        assert "minimum" in errors[0]

        errors = registry.validate_params("tool:range", {"count": 101})
        assert len(errors) == 1
        assert "maximum" in errors[0]

        errors = registry.validate_params("tool:range", {"count": 50})
        assert errors == []

    def test_enum_validation(self, tmp_path):
        yaml_text = """  "tool:enum":
    effect: "write"
    resource_type: "data"
    params_schema:
      type: object
      properties:
        status:
          type: string
          enum: ["active", "inactive"]"""
        registry = self._make_registry(tmp_path, yaml_text)

        errors = registry.validate_params("tool:enum", {"status": "deleted"})
        assert len(errors) == 1
        assert "enum" in errors[0]

        errors = registry.validate_params("tool:enum", {"status": "active"})
        assert errors == []

    def test_unknown_tool_returns_no_errors(self, tmp_path):
        registry = self._make_registry(tmp_path, '  "tool:a":\n    effect: "read"\n    resource_type: "data"')
        errors = registry.validate_params("unknown:tool", {"anything": True})
        assert errors == []

    @pytest.mark.asyncio
    async def test_tower_denies_invalid_params(self, tmp_path, agent_ctx, intent):
        """ControlTower should deny tool calls with invalid parameters."""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("""
version: "1.0.0"
tools:
  "tool:strict":
    effect: "write"
    resource_type: "file"
    params_schema:
      type: object
      required: [path]
      properties:
        path:
          type: string
          pattern: "^/safe/"
""")
        registry = ToolRegistry(manifest)
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(),
            MockApprover(),
            audit,
            registry=registry,
        )

        tool_req = ToolRequest(
            tool="tool:strict",
            action="write",
            resource_type="file",
            effect=Effect.WRITE,
            params={"path": "/unsafe/hack.txt"},
            manifest_version="1.0.0",
        )

        with pytest.raises(TollgateDenied, match="Parameter validation failed"):
            await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)

        assert audit.events[-1].outcome == Outcome.BLOCKED

    @pytest.mark.asyncio
    async def test_tower_allows_valid_params(self, tmp_path, agent_ctx, intent):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("""
version: "1.0.0"
tools:
  "tool:strict":
    effect: "write"
    resource_type: "file"
    params_schema:
      type: object
      required: [path]
      properties:
        path:
          type: string
          pattern: "^/safe/"
""")
        registry = ToolRegistry(manifest)
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(),
            MockApprover(),
            audit,
            registry=registry,
        )

        tool_req = ToolRequest(
            tool="tool:strict",
            action="write",
            resource_type="file",
            effect=Effect.WRITE,
            params={"path": "/safe/ok.txt"},
            manifest_version="1.0.0",
        )

        result = await tower.execute_async(
            agent_ctx, intent, tool_req, _noop_async
        )
        assert result == "ok"


# ─────────────────────────────────────────────────────────────────────
# 1.4 - READ Gating / Constraints
# ─────────────────────────────────────────────────────────────────────


class TestConstraints:
    def _make_registry(self, tmp_path, tools_yaml):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(f'version: "1.0.0"\ntools:\n{tools_yaml}')
        return ToolRegistry(manifest)

    def test_url_allowlist_blocks_unlisted(self, tmp_path):
        yaml_text = """  "fetch:url":
    effect: "read"
    resource_type: "url"
    constraints:
      allowed_url_patterns:
        - "https://api.github.com/*"
        - "https://arxiv.org/*" """
        registry = self._make_registry(tmp_path, yaml_text)

        violations = registry.check_constraints(
            "fetch:url", {"url": "https://evil.com/steal"}
        )
        assert len(violations) == 1
        assert "does not match any allowed URL pattern" in violations[0]

    def test_url_allowlist_passes_listed(self, tmp_path):
        yaml_text = """  "fetch:url":
    effect: "read"
    resource_type: "url"
    constraints:
      allowed_url_patterns:
        - "https://api.github.com/*" """
        registry = self._make_registry(tmp_path, yaml_text)

        violations = registry.check_constraints(
            "fetch:url", {"url": "https://api.github.com/repos"}
        )
        assert violations == []

    def test_url_blocklist(self, tmp_path):
        yaml_text = """  "fetch:url":
    effect: "read"
    resource_type: "url"
    constraints:
      blocked_url_patterns:
        - "http://*"
        - "*.internal.*" """
        registry = self._make_registry(tmp_path, yaml_text)

        violations = registry.check_constraints(
            "fetch:url", {"url": "http://insecure.com/data"}
        )
        assert len(violations) == 1
        assert "blocked pattern" in violations[0]

    def test_param_constraints_allowed_values(self, tmp_path):
        yaml_text = """  "db:query":
    effect: "read"
    resource_type: "database"
    constraints:
      param_constraints:
        table:
          allowed_values: ["users", "orders"] """
        registry = self._make_registry(tmp_path, yaml_text)

        violations = registry.check_constraints(
            "db:query", {"table": "admin_secrets"}
        )
        assert len(violations) == 1

        violations = registry.check_constraints(
            "db:query", {"table": "users"}
        )
        assert violations == []

    def test_no_constraints_means_no_violations(self, tmp_path):
        yaml_text = '  "tool:a":\n    effect: "read"\n    resource_type: "data"'
        registry = self._make_registry(tmp_path, yaml_text)
        assert registry.check_constraints("tool:a", {"anything": "ok"}) == []

    @pytest.mark.asyncio
    async def test_tower_blocks_constraint_violation(self, tmp_path, agent_ctx, intent):
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("""
version: "1.0.0"
tools:
  "fetch:url":
    effect: "read"
    resource_type: "url"
    constraints:
      allowed_url_patterns:
        - "https://safe.example.com/*"
""")
        registry = ToolRegistry(manifest)
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(),
            MockApprover(),
            audit,
            registry=registry,
        )

        tool_req = ToolRequest(
            tool="fetch:url",
            action="fetch",
            resource_type="url",
            effect=Effect.READ,
            params={"url": "https://evil.com/steal"},
            manifest_version="1.0.0",
        )

        with pytest.raises(TollgateConstraintViolation, match="Constraint violation"):
            await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)


# ─────────────────────────────────────────────────────────────────────
# 1.2 - Rate Limiting
# ─────────────────────────────────────────────────────────────────────


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_allows_within_limit(self, agent_ctx):
        limiter = InMemoryRateLimiter([
            {"agent_id": "*", "tool": "*", "max_calls": 5, "window_seconds": 60}
        ])
        req = ToolRequest("tool:a", "run", "data", Effect.READ, {})

        for _ in range(5):
            allowed, reason, _ = await limiter.check_rate_limit(agent_ctx, req)
            assert allowed is True
            assert reason is None

    @pytest.mark.asyncio
    async def test_blocks_over_limit(self, agent_ctx):
        limiter = InMemoryRateLimiter([
            {"agent_id": "*", "tool": "*", "max_calls": 3, "window_seconds": 60}
        ])
        req = ToolRequest("tool:a", "run", "data", Effect.READ, {})

        for _ in range(3):
            allowed, _, _ = await limiter.check_rate_limit(agent_ctx, req)
            assert allowed is True

        # 4th call should be blocked
        allowed, reason, retry_after = await limiter.check_rate_limit(agent_ctx, req)
        assert allowed is False
        assert reason is not None
        assert "Rate limit exceeded" in reason
        assert retry_after is not None

    @pytest.mark.asyncio
    async def test_effect_specific_limit(self, agent_ctx):
        limiter = InMemoryRateLimiter([
            {"agent_id": "*", "tool": "*", "effect": "write", "max_calls": 2, "window_seconds": 60}
        ])
        read_req = ToolRequest("tool:a", "run", "data", Effect.READ, {})
        write_req = ToolRequest("tool:a", "run", "data", Effect.WRITE, {})

        # READ calls should not be limited by the write rule
        for _ in range(10):
            allowed, _, _ = await limiter.check_rate_limit(agent_ctx, read_req)
            assert allowed is True

        # WRITE calls should be limited
        for _ in range(2):
            allowed, _, _ = await limiter.check_rate_limit(agent_ctx, write_req)
            assert allowed is True

        allowed, reason, _ = await limiter.check_rate_limit(agent_ctx, write_req)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_tool_prefix_matching(self, agent_ctx):
        limiter = InMemoryRateLimiter([
            {"agent_id": "*", "tool": "mcp:*", "max_calls": 2, "window_seconds": 60}
        ])
        mcp_req = ToolRequest("mcp:server.tool", "run", "data", Effect.READ, {})
        other_req = ToolRequest("langchain:tool", "run", "data", Effect.READ, {})

        for _ in range(2):
            allowed, _, _ = await limiter.check_rate_limit(agent_ctx, mcp_req)
            assert allowed is True

        # MCP tool blocked
        allowed, _, _ = await limiter.check_rate_limit(agent_ctx, mcp_req)
        assert allowed is False

        # Non-MCP tool still allowed
        allowed, _, _ = await limiter.check_rate_limit(agent_ctx, other_req)
        assert allowed is True

    @pytest.mark.asyncio
    async def test_reset_clears_state(self, agent_ctx):
        limiter = InMemoryRateLimiter([
            {"agent_id": "*", "tool": "*", "max_calls": 1, "window_seconds": 60}
        ])
        req = ToolRequest("tool:a", "run", "data", Effect.READ, {})

        allowed, _, _ = await limiter.check_rate_limit(agent_ctx, req)
        assert allowed is True

        allowed, _, _ = await limiter.check_rate_limit(agent_ctx, req)
        assert allowed is False

        await limiter.reset()

        allowed, _, _ = await limiter.check_rate_limit(agent_ctx, req)
        assert allowed is True

    @pytest.mark.asyncio
    async def test_tower_raises_rate_limited(self, agent_ctx, intent, tool_req):
        limiter = InMemoryRateLimiter([
            {"agent_id": "*", "tool": "*", "max_calls": 1, "window_seconds": 60}
        ])
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(),
            MockApprover(),
            audit,
            rate_limiter=limiter,
        )

        # First call succeeds
        result = await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)
        assert result == "ok"

        # Second call rate limited
        with pytest.raises(TollgateRateLimited, match="Rate limit"):
            await tower.execute_async(agent_ctx, intent, tool_req, _noop_async)

        # Verify audit logged the block
        blocked = [e for e in audit.events if e.outcome == Outcome.BLOCKED]
        assert len(blocked) == 1


# ─────────────────────────────────────────────────────────────────────
# 1.6 - Agent Identity HMAC Signing
# ─────────────────────────────────────────────────────────────────────


class TestAgentIdentityVerification:
    def test_sign_and_verify(self):
        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="team-a")
        secret = b"test-secret-key"

        signed = sign_agent_context(ctx, secret)
        assert "_signature" in signed.metadata
        assert verify_agent_context(signed, secret) is True

    def test_verify_fails_wrong_key(self):
        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="team-a")
        signed = sign_agent_context(ctx, b"correct-key")
        assert verify_agent_context(signed, b"wrong-key") is False

    def test_verify_fails_tampered_agent_id(self):
        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="team-a")
        secret = b"test-key"
        signed = sign_agent_context(ctx, secret)

        # Tamper with agent_id
        from dataclasses import replace
        tampered = replace(signed, agent_id="agent-evil")
        assert verify_agent_context(tampered, secret) is False

    def test_verify_fails_no_signature(self):
        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="team-a")
        assert verify_agent_context(ctx, b"key") is False

    def test_make_verifier_creates_callable(self):
        secret = b"test-key"
        verifier = make_verifier(secret)

        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="team-a")
        signed = sign_agent_context(ctx, secret)

        assert verifier(signed) is True
        assert verifier(ctx) is False  # Unsigned

    @pytest.mark.asyncio
    async def test_tower_denies_unverified_agent(self, intent, tool_req):
        secret = b"tower-secret"
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(),
            MockApprover(),
            audit,
            verify_fn=make_verifier(secret),
        )

        # Unsigned agent context
        unsigned_ctx = AgentContext(agent_id="agent-1", version="1.0", owner="team-a")

        with pytest.raises(TollgateDenied, match="identity verification failed"):
            await tower.execute_async(unsigned_ctx, intent, tool_req, _noop_async)

        assert audit.events[-1].outcome == Outcome.BLOCKED

    @pytest.mark.asyncio
    async def test_tower_allows_verified_agent(self, intent, tool_req):
        secret = b"tower-secret"
        audit = MockAudit()
        tower = ControlTower(
            MockPolicy(),
            MockApprover(),
            audit,
            verify_fn=make_verifier(secret),
        )

        signed_ctx = sign_agent_context(
            AgentContext(agent_id="agent-1", version="1.0", owner="team-a"),
            secret,
        )

        result = await tower.execute_async(signed_ctx, intent, tool_req, _noop_async)
        assert result == "ok"


# ─────────────────────────────────────────────────────────────────────
# Integration: Multiple features together
# ─────────────────────────────────────────────────────────────────────


class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_pipeline_identity_rate_schema_constraints(self, tmp_path, intent):
        """Test all Month 1 features working together in the enforcement pipeline."""
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("""
version: "1.0.0"
tools:
  "api:fetch":
    effect: "read"
    resource_type: "url"
    params_schema:
      type: object
      required: [url]
      properties:
        url:
          type: string
    constraints:
      allowed_url_patterns:
        - "https://api.github.com/*"
""")
        registry = ToolRegistry(manifest)
        secret = b"integration-secret"
        limiter = InMemoryRateLimiter([
            {"agent_id": "*", "tool": "*", "max_calls": 10, "window_seconds": 60}
        ])
        audit = MockAudit()

        tower = ControlTower(
            MockPolicy(),
            MockApprover(),
            audit,
            rate_limiter=limiter,
            registry=registry,
            verify_fn=make_verifier(secret),
        )

        signed_ctx = sign_agent_context(
            AgentContext(agent_id="agent-1", version="1.0", owner="team-a"),
            secret,
        )
        good_req = ToolRequest(
            tool="api:fetch",
            action="get",
            resource_type="url",
            effect=Effect.READ,
            params={"url": "https://api.github.com/repos"},
            manifest_version="1.0.0",
        )

        # Should pass: signed identity, within rate limit, valid params, allowed URL
        result = await tower.execute_async(signed_ctx, intent, good_req, _noop_async)
        assert result == "ok"

        # Should fail: constraint violation (wrong URL)
        bad_url_req = ToolRequest(
            tool="api:fetch",
            action="get",
            resource_type="url",
            effect=Effect.READ,
            params={"url": "https://evil.com/steal"},
            manifest_version="1.0.0",
        )
        with pytest.raises(TollgateConstraintViolation):
            await tower.execute_async(signed_ctx, intent, bad_url_req, _noop_async)


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


async def _noop_async():
    return "ok"
