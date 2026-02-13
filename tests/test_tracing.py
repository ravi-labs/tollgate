"""Tests for OpenTelemetry distributed tracing."""

from unittest.mock import MagicMock, patch

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


def _mock_init(self, **kwargs):  # noqa: ARG001
    """Mock init function for OTelTracingAuditSink."""
    pass


@pytest.fixture
def agent_ctx():
    """Create a test agent context."""
    return AgentContext(
        agent_id="test-agent",
        version="1.0",
        owner="test-owner",
        metadata={"org_id": "org-123"},
    )


@pytest.fixture
def tool_request():
    """Create a test tool request."""
    return ToolRequest(
        tool="api:fetch",
        action="get",
        resource_type="url",
        effect=Effect.READ,
        params={"url": "https://example.com"},
    )


@pytest.fixture
def intent():
    """Create a test intent."""
    return Intent(action="fetch", reason="Fetch data from API")


@pytest.fixture
def allow_decision():
    """Create an ALLOW decision."""
    return Decision(
        decision=DecisionType.ALLOW,
        reason="Allowed by policy",
        policy_id="allow_read",
    )


@pytest.fixture
def ask_decision():
    """Create an ASK decision."""
    return Decision(
        decision=DecisionType.ASK,
        reason="Requires approval",
        policy_id="ask_sensitive",
    )


@pytest.fixture
def audit_event(agent_ctx, tool_request, intent, allow_decision):
    """Create a test audit event."""
    from datetime import datetime, timezone

    return AuditEvent(
        correlation_id="corr-123",
        timestamp=datetime.now(timezone.utc).isoformat(),
        request_hash="hash-123",
        agent=agent_ctx,
        intent=intent,
        tool_request=tool_request,
        decision=allow_decision,
        outcome=Outcome.EXECUTED,
        grant_id="grant-456",
    )


@pytest.fixture
def mock_tracer_provider():
    """Create a mock tracer provider."""
    mock_provider = MagicMock()
    mock_tracer = MagicMock()
    mock_span = MagicMock()

    mock_provider.get_tracer.return_value = mock_tracer
    mock_tracer.start_span.return_value = mock_span

    # Setup start_as_current_span as context manager
    mock_span_cm = MagicMock()
    mock_span_cm.__enter__ = MagicMock(return_value=mock_span)
    mock_span_cm.__exit__ = MagicMock(return_value=None)
    mock_tracer.start_as_current_span.return_value = mock_span_cm

    return mock_provider, mock_tracer, mock_span


class TestOTelTracingAuditSink:
    """Tests for OTelTracingAuditSink."""

    @pytest.fixture
    def tracing_sink(self, mock_tracer_provider):
        """Create a tracing sink with mocked provider."""
        mock_provider, _, _ = mock_tracer_provider

        with patch(
            "tollgate.otel.OTelTracingAuditSink.__init__",
            _mock_init
        ):
            from tollgate.otel import OTelTracingAuditSink

            sink = OTelTracingAuditSink.__new__(OTelTracingAuditSink)
            sink._tracer = mock_provider.get_tracer("tollgate", "1.0")
            sink._active_spans = {}
            return sink

    def test_start_span_creates_span(self, tracing_sink, mock_tracer_provider):
        """Test that start_span creates a new span."""
        _, mock_tracer, _ = mock_tracer_provider

        tracing_sink.start_span("corr-123")

        mock_tracer.start_span.assert_called_once()
        call_kwargs = mock_tracer.start_span.call_args
        assert call_kwargs[1]["name"] == "tollgate.execute"
        assert "corr-123" in tracing_sink._active_spans

    def test_end_span_ends_span(self, tracing_sink, mock_tracer_provider):
        """Test that end_span ends the span."""
        _, _, mock_span = mock_tracer_provider

        tracing_sink.start_span("corr-123")
        tracing_sink.end_span("corr-123")

        mock_span.end.assert_called_once()
        assert "corr-123" not in tracing_sink._active_spans

    def test_end_span_noop_for_unknown(self, tracing_sink):
        """Test that end_span does nothing for unknown correlation_id."""
        # Should not raise
        tracing_sink.end_span("unknown-id")

    def test_emit_creates_parent_span_if_needed(
        self, tracing_sink, mock_tracer_provider, audit_event
    ):
        """Test that emit creates parent span if none exists."""
        _, mock_tracer, mock_span = mock_tracer_provider

        tracing_sink.emit(audit_event)

        # Should have started a span
        mock_tracer.start_span.assert_called()

    def test_emit_sets_agent_attributes(
        self, tracing_sink, mock_tracer_provider, audit_event
    ):
        """Test that emit sets agent attributes on span."""
        _, mock_tracer, mock_span = mock_tracer_provider

        # Start span first
        tracing_sink.start_span(audit_event.correlation_id)
        tracing_sink.emit(audit_event)

        # Check attributes were set
        calls = mock_span.set_attribute.call_args_list
        attrs = {call[0][0]: call[0][1] for call in calls}

        assert attrs.get("tollgate.agent.id") == "test-agent"
        assert attrs.get("tollgate.agent.version") == "1.0"
        assert attrs.get("tollgate.agent.owner") == "test-owner"
        assert attrs.get("tollgate.org.id") == "org-123"

    def test_emit_sets_tool_attributes(
        self, tracing_sink, mock_tracer_provider, audit_event
    ):
        """Test that emit sets tool attributes on span."""
        _, _, mock_span = mock_tracer_provider

        tracing_sink.start_span(audit_event.correlation_id)
        tracing_sink.emit(audit_event)

        calls = mock_span.set_attribute.call_args_list
        attrs = {call[0][0]: call[0][1] for call in calls}

        assert attrs.get("tollgate.tool.name") == "api:fetch"
        assert attrs.get("tollgate.tool.action") == "get"
        assert attrs.get("tollgate.tool.effect") == "read"

    def test_emit_sets_decision_attributes(
        self, tracing_sink, mock_tracer_provider, audit_event
    ):
        """Test that emit sets decision attributes on span."""
        _, _, mock_span = mock_tracer_provider

        tracing_sink.start_span(audit_event.correlation_id)
        tracing_sink.emit(audit_event)

        calls = mock_span.set_attribute.call_args_list
        attrs = {call[0][0]: call[0][1] for call in calls}

        assert attrs.get("tollgate.decision.type") == "ALLOW"
        assert attrs.get("tollgate.decision.reason") == "Allowed by policy"
        assert attrs.get("tollgate.decision.policy_id") == "allow_read"

    def test_emit_sets_grant_id_when_present(
        self, tracing_sink, mock_tracer_provider, audit_event
    ):
        """Test that emit sets grant_id when present."""
        _, _, mock_span = mock_tracer_provider

        tracing_sink.start_span(audit_event.correlation_id)
        tracing_sink.emit(audit_event)

        calls = mock_span.set_attribute.call_args_list
        attrs = {call[0][0]: call[0][1] for call in calls}

        assert attrs.get("tollgate.grant.id") == "grant-456"

    def test_emit_sets_outcome_attribute(
        self, tracing_sink, mock_tracer_provider, audit_event
    ):
        """Test that emit sets outcome attribute."""
        _, _, mock_span = mock_tracer_provider

        tracing_sink.start_span(audit_event.correlation_id)
        tracing_sink.emit(audit_event)

        calls = mock_span.set_attribute.call_args_list
        attrs = {call[0][0]: call[0][1] for call in calls}

        assert attrs.get("tollgate.outcome") == "executed"

    def test_emit_creates_policy_child_span(
        self, tracing_sink, mock_tracer_provider, audit_event
    ):
        """Test that emit creates a child span for policy evaluation."""
        _, mock_tracer, _ = mock_tracer_provider

        tracing_sink.start_span(audit_event.correlation_id)
        tracing_sink.emit(audit_event)

        # Should have called start_as_current_span for child spans
        calls = mock_tracer.start_as_current_span.call_args_list
        span_names = [call[0][0] for call in calls]

        assert "tollgate.policy.evaluate" in span_names

    def test_emit_creates_grant_child_span_when_grant_used(
        self, tracing_sink, mock_tracer_provider, audit_event
    ):
        """Test that emit creates grant child span when grant is used."""
        _, mock_tracer, _ = mock_tracer_provider

        tracing_sink.start_span(audit_event.correlation_id)
        tracing_sink.emit(audit_event)

        calls = mock_tracer.start_as_current_span.call_args_list
        span_names = [call[0][0] for call in calls]

        assert "tollgate.grant.check" in span_names


class TestTracingWithASKDecision:
    """Tests for tracing with ASK decisions."""

    @pytest.fixture
    def ask_audit_event(self, agent_ctx, tool_request, intent, ask_decision):
        """Create an audit event with ASK decision."""
        from datetime import datetime, timezone

        return AuditEvent(
            correlation_id="corr-ask-123",
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_hash="hash-ask-123",
            agent=agent_ctx,
            intent=intent,
            tool_request=tool_request,
            decision=ask_decision,
            outcome=Outcome.BLOCKED,
            grant_id=None,  # No grant - approval required
        )

    @pytest.fixture
    def tracing_sink(self, mock_tracer_provider):
        """Create a tracing sink with mocked provider."""
        mock_provider, _, _ = mock_tracer_provider

        with patch(
            "tollgate.otel.OTelTracingAuditSink.__init__",
            _mock_init
        ):
            from tollgate.otel import OTelTracingAuditSink

            sink = OTelTracingAuditSink.__new__(OTelTracingAuditSink)
            sink._tracer = mock_provider.get_tracer("tollgate", "1.0")
            sink._active_spans = {}
            return sink

    def test_emit_creates_approval_span_for_ask_without_grant(
        self, tracing_sink, mock_tracer_provider, ask_audit_event
    ):
        """Test that approval span is created for ASK decision without grant."""
        _, mock_tracer, _ = mock_tracer_provider

        tracing_sink.start_span(ask_audit_event.correlation_id)
        tracing_sink.emit(ask_audit_event)

        calls = mock_tracer.start_as_current_span.call_args_list
        span_names = [call[0][0] for call in calls]

        assert "tollgate.approval.request" in span_names


class TestTracingContextManager:
    """Tests for TracingContextManager."""

    def test_context_manager_starts_and_ends_span(self, mock_tracer_provider):
        """Test that context manager properly starts and ends span."""
        mock_provider, mock_tracer, mock_span = mock_tracer_provider

        with patch(
            "tollgate.otel.OTelTracingAuditSink.__init__",
            _mock_init
        ):
            from tollgate.otel import OTelTracingAuditSink, TracingContextManager

            sink = OTelTracingAuditSink.__new__(OTelTracingAuditSink)
            sink._tracer = mock_tracer
            sink._active_spans = {}

            with TracingContextManager(sink, "corr-ctx-123") as span:
                assert span is mock_span
                assert "corr-ctx-123" in sink._active_spans

            # After exiting, span should be ended
            mock_span.end.assert_called_once()
            assert "corr-ctx-123" not in sink._active_spans

    def test_context_manager_records_exception(self, mock_tracer_provider):
        """Test that context manager records exceptions."""
        mock_provider, mock_tracer, mock_span = mock_tracer_provider

        with patch(
            "tollgate.otel.OTelTracingAuditSink.__init__",
            _mock_init
        ):
            from tollgate.otel import OTelTracingAuditSink, TracingContextManager

            sink = OTelTracingAuditSink.__new__(OTelTracingAuditSink)
            sink._tracer = mock_tracer
            sink._active_spans = {}

            with (
                pytest.raises(ValueError),
                TracingContextManager(sink, "corr-err-123"),
            ):
                raise ValueError("Test error")

            # Should have recorded the exception
            mock_span.record_exception.assert_called_once()
            mock_span.set_status.assert_called()


class TestTracingSinkIntegration:
    """Integration tests requiring actual OTel packages."""

    @pytest.mark.skipif(
        not pytest.importorskip("opentelemetry", reason="OTel not installed"),
        reason="OpenTelemetry not installed"
    )
    def test_tracing_sink_initialization(self):
        """Test that tracing sink initializes with real OTel."""
        from opentelemetry.sdk.trace import TracerProvider

        from tollgate.otel import OTelTracingAuditSink

        provider = TracerProvider()
        sink = OTelTracingAuditSink(tracer_provider=provider)

        assert sink._tracer is not None
        assert sink._active_spans == {}

    @pytest.mark.skipif(
        not pytest.importorskip("opentelemetry", reason="OTel not installed"),
        reason="OpenTelemetry not installed"
    )
    def test_span_lifecycle(self, agent_ctx, tool_request, intent, allow_decision):
        """Test full span lifecycle with real OTel."""
        from datetime import datetime, timezone

        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        from tollgate.otel import OTelTracingAuditSink

        # Setup in-memory exporter to capture spans
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))

        sink = OTelTracingAuditSink(tracer_provider=provider)

        # Create and emit audit event
        event = AuditEvent(
            correlation_id="test-corr-id",
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_hash="hash-lifecycle-test",
            agent=agent_ctx,
            intent=intent,
            tool_request=tool_request,
            decision=allow_decision,
            outcome=Outcome.EXECUTED,
            grant_id="test-grant-id",
        )

        # Use context manager
        with sink.trace("test-corr-id"):
            sink.emit(event)

        # Get exported spans
        spans = exporter.get_finished_spans()

        # Should have parent span plus child spans
        assert len(spans) >= 2  # At least parent and policy.evaluate

        # Find the parent span
        parent_span = next(
            (s for s in spans if s.name == "tollgate.execute"),
            None
        )
        assert parent_span is not None

    @pytest.mark.skipif(
        not pytest.importorskip("opentelemetry", reason="OTel not installed"),
        reason="OpenTelemetry not installed"
    )
    def test_create_otel_tracing_sink_factory(self):
        """Test the factory function for creating tracing sink."""
        # Note: This test may fail without an actual OTLP endpoint
        # We just test that it doesn't raise during initialization
        from tollgate.otel import create_otel_tracing_sink

        # Should not raise during initialization
        sink = create_otel_tracing_sink(endpoint="localhost:4317")
        assert sink is not None


class TestFactoryFunctions:
    """Tests for factory functions."""

    @pytest.mark.skipif(
        not pytest.importorskip("opentelemetry", reason="OTel not installed"),
        reason="OpenTelemetry not installed"
    )
    def test_create_otel_sinks_returns_tuple(self):
        """Test that create_otel_sinks returns both metrics and tracing sinks."""
        from tollgate.otel import (
            OTelMetricsAuditSink,
            OTelTracingAuditSink,
            create_otel_sinks,
        )

        metrics_sink, tracing_sink = create_otel_sinks(endpoint="localhost:4317")

        assert isinstance(metrics_sink, OTelMetricsAuditSink)
        assert isinstance(tracing_sink, OTelTracingAuditSink)


class TestSpanStatus:
    """Tests for span status based on outcome."""

    @pytest.fixture
    def tracing_sink(self, mock_tracer_provider):
        """Create a tracing sink with mocked provider."""
        mock_provider, _, _ = mock_tracer_provider

        with patch(
            "tollgate.otel.OTelTracingAuditSink.__init__",
            _mock_init
        ):
            from tollgate.otel import OTelTracingAuditSink

            sink = OTelTracingAuditSink.__new__(OTelTracingAuditSink)
            sink._tracer = mock_provider.get_tracer("tollgate", "1.0")
            sink._active_spans = {}
            return sink

    @pytest.mark.parametrize("outcome,expected_ok", [
        (Outcome.EXECUTED, True),
        (Outcome.BLOCKED, False),
        (Outcome.FAILED, False),
        (Outcome.TIMEOUT, False),
        (Outcome.APPROVAL_DENIED, False),
    ])
    def test_span_status_based_on_outcome(
        self,
        tracing_sink,
        mock_tracer_provider,
        agent_ctx,
        tool_request,
        intent,
        allow_decision,
        outcome,
        expected_ok,
    ):
        """Test that span status is set correctly based on outcome."""
        from datetime import datetime, timezone

        _, _, mock_span = mock_tracer_provider

        event = AuditEvent(
            correlation_id="corr-status-test",
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_hash="hash-status-test",
            agent=agent_ctx,
            intent=intent,
            tool_request=tool_request,
            decision=allow_decision,
            outcome=outcome,
            grant_id=None,
        )

        tracing_sink.start_span(event.correlation_id)
        tracing_sink.emit(event)

        # Check that set_status was called
        mock_span.set_status.assert_called()

        # Get the status argument
        status_call = mock_span.set_status.call_args[0][0]

        # Check the status code
        from opentelemetry.trace import StatusCode

        if expected_ok:
            assert status_call.status_code == StatusCode.OK
        else:
            assert status_call.status_code == StatusCode.ERROR
