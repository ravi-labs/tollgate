"""Tests for OpenTelemetry metrics integration."""

import pytest

# Skip all tests if OTel not installed
otel = pytest.importorskip("opentelemetry")

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from tollgate import (
    AgentContext,
    Decision,
    DecisionType,
    Effect,
    Intent,
    Outcome,
    ToolRequest,
)
from tollgate.otel import OTelMetricsAuditSink
from tollgate.types import AuditEvent


@pytest.fixture
def metric_reader():
    return InMemoryMetricReader()


@pytest.fixture
def otel_sink(metric_reader):
    provider = MeterProvider(metric_readers=[metric_reader])
    return OTelMetricsAuditSink(meter_provider=provider)


@pytest.fixture
def sample_event():
    return AuditEvent(
        timestamp="2024-01-01T00:00:00Z",
        correlation_id="test-123",
        request_hash="abc",
        agent=AgentContext(agent_id="agent-1", version="1.0", owner="user"),
        intent=Intent(action="test", reason="testing"),
        tool_request=ToolRequest(
            tool="test_tool",
            action="run",
            resource_type="data",
            effect=Effect.READ,
            params={},
        ),
        decision=Decision(
            decision=DecisionType.ALLOW,
            reason="test",
        ),
        outcome=Outcome.EXECUTED,
    )


class TestOTelMetricsAuditSink:
    def test_otel_sink_emits_decision_counter(
        self, otel_sink, metric_reader, sample_event
    ):
        otel_sink.emit(sample_event)

        metrics = metric_reader.get_metrics_data()
        assert metrics is not None

        # Find the decisions counter
        for resource_metric in metrics.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == "tollgate.decisions.total":
                        # Verify we have data points
                        assert len(metric.data.data_points) > 0
                        return

        pytest.fail("tollgate.decisions.total metric not found")

    def test_otel_sink_emits_outcome_counter(
        self, otel_sink, metric_reader, sample_event
    ):
        otel_sink.emit(sample_event)

        metrics = metric_reader.get_metrics_data()
        assert metrics is not None

        # Find the outcomes counter
        for resource_metric in metrics.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == "tollgate.outcomes.total":
                        assert len(metric.data.data_points) > 0
                        return

        pytest.fail("tollgate.outcomes.total metric not found")

    def test_otel_sink_tracks_duration(self, otel_sink, metric_reader, sample_event):
        # Record start time
        otel_sink.record_start(sample_event.correlation_id)

        # Small delay to ensure measurable duration
        import time

        time.sleep(0.001)

        # Emit the event
        otel_sink.emit(sample_event)

        metrics = metric_reader.get_metrics_data()
        assert metrics is not None

        # Find the duration histogram
        for resource_metric in metrics.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == "tollgate.execution.duration_ms":
                        assert len(metric.data.data_points) > 0
                        return

        pytest.fail("tollgate.execution.duration_ms metric not found")

    def test_otel_sink_includes_org_id_when_present(self, otel_sink, metric_reader):
        event = AuditEvent(
            timestamp="2024-01-01T00:00:00Z",
            correlation_id="test-123",
            request_hash="abc",
            agent=AgentContext(
                agent_id="agent-1",
                version="1.0",
                owner="user",
                metadata={"org_id": "org-123"},
            ),
            intent=Intent(action="test", reason="testing"),
            tool_request=ToolRequest(
                tool="test_tool",
                action="run",
                resource_type="data",
                effect=Effect.READ,
                params={},
            ),
            decision=Decision(decision=DecisionType.ALLOW, reason="test"),
            outcome=Outcome.EXECUTED,
        )
        otel_sink.emit(event)

        metrics = metric_reader.get_metrics_data()
        assert metrics is not None

        # Find the decisions counter and check org_id attribute
        for resource_metric in metrics.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == "tollgate.decisions.total":
                        for dp in metric.data.data_points:
                            attrs = dict(dp.attributes)
                            assert attrs.get("org_id") == "org-123"
                            return

        pytest.fail("Decision counter with org_id attribute not found")

    def test_otel_sink_tracks_grant_usage(self, otel_sink, metric_reader):
        event = AuditEvent(
            timestamp="2024-01-01T00:00:00Z",
            correlation_id="test-123",
            request_hash="abc",
            agent=AgentContext(agent_id="agent-1", version="1.0", owner="user"),
            intent=Intent(action="test", reason="testing"),
            tool_request=ToolRequest(
                tool="test_tool",
                action="run",
                resource_type="data",
                effect=Effect.READ,
                params={},
            ),
            decision=Decision(decision=DecisionType.ASK, reason="needs approval"),
            outcome=Outcome.EXECUTED,
            grant_id="grant-123",  # Grant was used
        )
        otel_sink.emit(event)

        metrics = metric_reader.get_metrics_data()
        assert metrics is not None

        # Find the grants counter
        for resource_metric in metrics.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == "tollgate.grants.used.total":
                        assert len(metric.data.data_points) > 0
                        return

        pytest.fail("tollgate.grants.used.total metric not found")

    def test_otel_sink_tracks_approval_requests(self, otel_sink, metric_reader):
        event = AuditEvent(
            timestamp="2024-01-01T00:00:00Z",
            correlation_id="test-123",
            request_hash="abc",
            agent=AgentContext(agent_id="agent-1", version="1.0", owner="user"),
            intent=Intent(action="test", reason="testing"),
            tool_request=ToolRequest(
                tool="test_tool",
                action="run",
                resource_type="data",
                effect=Effect.WRITE,
                params={},
            ),
            decision=Decision(decision=DecisionType.ASK, reason="needs approval"),
            outcome=Outcome.EXECUTED,
            grant_id=None,  # No grant, approval was requested
        )
        otel_sink.emit(event)

        metrics = metric_reader.get_metrics_data()
        assert metrics is not None

        # Find the approvals counter
        for resource_metric in metrics.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == "tollgate.approvals.requested.total":
                        assert len(metric.data.data_points) > 0
                        return

        pytest.fail("tollgate.approvals.requested.total metric not found")

    def test_otel_sink_never_raises_on_emit(self, metric_reader, sample_event):
        """Ensure metrics failures don't propagate."""
        provider = MeterProvider(metric_readers=[metric_reader])
        sink = OTelMetricsAuditSink(meter_provider=provider)

        # Should not raise even if something goes wrong internally
        sink.emit(sample_event)

    def test_otel_sink_handles_missing_start_time(
        self, otel_sink, metric_reader, sample_event
    ):
        """Duration should not be recorded if record_start was never called."""
        # Don't call record_start
        otel_sink.emit(sample_event)

        metrics = metric_reader.get_metrics_data()
        assert metrics is not None

        # Duration histogram should exist but have no data points
        # (or have 0 count since start time wasn't recorded)
        for resource_metric in metrics.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == "tollgate.execution.duration_ms":
                        # Should have no data points since record_start wasn't called
                        assert len(metric.data.data_points) == 0
                        return

    def test_otel_sink_includes_all_base_attributes(
        self, otel_sink, metric_reader, sample_event
    ):
        otel_sink.emit(sample_event)

        metrics = metric_reader.get_metrics_data()
        assert metrics is not None

        # Find decisions counter and verify attributes
        for resource_metric in metrics.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    if metric.name == "tollgate.decisions.total":
                        for dp in metric.data.data_points:
                            attrs = dict(dp.attributes)
                            assert "agent_id" in attrs
                            assert "tool" in attrs
                            assert "effect" in attrs
                            assert "decision_type" in attrs
                            assert attrs["agent_id"] == "agent-1"
                            assert attrs["tool"] == "test_tool"
                            assert attrs["effect"] == "read"
                            assert attrs["decision_type"] == "ALLOW"
                            return

        pytest.fail("Decision counter with expected attributes not found")
