"""Tests for SLO Monitoring & Alerting."""

import pytest

from tollgate.slo import (
    AlertSeverity,
    SLOAlert,
    SLOAuditSink,
    SLOConfig,
    SLOMetrics,
    SLOMonitor,
    SLOType,
)


class TestSLOConfig:
    """Tests for SLOConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SLOConfig()

        assert config.availability_target == 0.999
        assert config.latency_p99_ms == 1000
        assert config.error_rate_max == 0.01
        assert config.window_size == 1000

    def test_custom_config(self):
        """Test custom configuration."""
        config = SLOConfig(
            availability_target=0.99,
            latency_p99_ms=500,
            error_rate_max=0.05,
        )

        assert config.availability_target == 0.99
        assert config.latency_p99_ms == 500
        assert config.error_rate_max == 0.05


class TestSLOAlert:
    """Tests for SLOAlert."""

    def test_to_dict(self):
        """Test converting alert to dictionary."""
        alert = SLOAlert(
            slo_type=SLOType.AVAILABILITY,
            severity=AlertSeverity.CRITICAL,
            current_value=0.95,
            threshold=0.999,
            message="Availability below target",
            timestamp=1234567890.0,
        )

        d = alert.to_dict()

        assert d["slo_type"] == "availability"
        assert d["severity"] == "critical"
        assert d["current_value"] == 0.95
        assert d["threshold"] == 0.999


class TestSLOMetrics:
    """Tests for SLOMetrics."""

    def test_to_dict(self):
        """Test converting metrics to dictionary."""
        metrics = SLOMetrics(
            timestamp=1234567890.0,
            total_executions=100,
            successful_executions=95,
            failed_executions=5,
            availability=0.95,
            latency_p50_ms=50,
            latency_p95_ms=200,
            latency_p99_ms=500,
            error_rate=0.05,
            allow_count=80,
            ask_count=15,
            deny_count=5,
            approval_rate=0.95,
            denial_rate=0.05,
        )

        d = metrics.to_dict()

        assert d["total_executions"] == 100
        assert d["availability"] == 0.95
        assert d["latency_p99_ms"] == 500


class TestSLOMonitor:
    """Tests for SLOMonitor."""

    @pytest.fixture
    def monitor(self):
        """Create a monitor with default config."""
        return SLOMonitor(SLOConfig(min_samples=5))

    @pytest.fixture
    def strict_monitor(self):
        """Create a monitor with strict SLOs."""
        return SLOMonitor(SLOConfig(
            availability_target=0.99,
            latency_p99_ms=100,
            error_rate_max=0.01,
            min_samples=5,
        ))

    def test_record_execution_success(self, monitor):
        """Test recording successful executions."""
        for _ in range(10):
            monitor.record_execution(duration_ms=50, success=True)

        metrics = monitor.get_metrics()

        assert metrics.total_executions == 10
        assert metrics.successful_executions == 10
        assert metrics.failed_executions == 0
        assert metrics.availability == 1.0

    def test_record_execution_failure(self, monitor):
        """Test recording failed executions."""
        for _ in range(8):
            monitor.record_execution(duration_ms=50, success=True)
        for _ in range(2):
            monitor.record_execution(duration_ms=50, success=False)

        metrics = monitor.get_metrics()

        assert metrics.total_executions == 10
        assert metrics.successful_executions == 8
        assert metrics.failed_executions == 2
        assert metrics.availability == 0.8
        assert metrics.error_rate == 0.2

    def test_record_decision(self, monitor):
        """Test recording decisions."""
        for _ in range(5):
            monitor.record_decision("ALLOW")
        for _ in range(3):
            monitor.record_decision("ASK")
        for _ in range(2):
            monitor.record_decision("DENY")

        metrics = monitor.get_metrics()

        assert metrics.allow_count == 5
        assert metrics.ask_count == 3
        assert metrics.deny_count == 2
        assert metrics.approval_rate == 0.8  # (5 + 3) / 10
        assert metrics.denial_rate == 0.2

    def test_latency_percentiles(self, monitor):
        """Test latency percentile calculations."""
        # Record 100 executions with increasing latencies
        for i in range(100):
            monitor.record_execution(duration_ms=i + 1, success=True)

        metrics = monitor.get_metrics()

        # P50 should be around 50
        assert 45 <= metrics.latency_p50_ms <= 55
        # P95 should be around 95
        assert 90 <= metrics.latency_p95_ms <= 100
        # P99 should be around 99
        assert 95 <= metrics.latency_p99_ms <= 100

    def test_alert_on_availability_breach(self, strict_monitor):
        """Test alert when availability drops below target."""
        alerts = []
        strict_monitor.on_alert(alerts.append)

        # Record some failures to drop availability
        for _ in range(8):
            strict_monitor.record_execution(50, success=True)
        for _ in range(2):
            strict_monitor.record_execution(50, success=False)

        # Should have received a critical alert
        assert len(alerts) > 0
        availability_alerts = [
            a for a in alerts if a.slo_type == SLOType.AVAILABILITY
        ]
        assert len(availability_alerts) > 0
        assert availability_alerts[0].severity == AlertSeverity.CRITICAL

    def test_alert_on_latency_breach(self, strict_monitor):
        """Test alert when latency exceeds threshold."""
        alerts = []
        strict_monitor.on_alert(alerts.append)

        # Record slow executions
        for _ in range(10):
            strict_monitor.record_execution(200, success=True)  # > 100ms threshold

        # Should have received latency alerts
        latency_alerts = [
            a for a in alerts if a.slo_type == SLOType.LATENCY_P99
        ]
        assert len(latency_alerts) > 0
        assert latency_alerts[0].severity == AlertSeverity.CRITICAL

    def test_alert_recovery(self):
        """Test recovery alert when SLO returns to healthy."""
        # Use small window so recovery is visible
        monitor = SLOMonitor(SLOConfig(
            availability_target=0.99,
            error_rate_max=0.01,
            window_size=20,
            min_samples=5,
        ))
        alerts = []
        monitor.on_alert(alerts.append)

        # First, breach the SLO with failures
        for _ in range(10):
            monitor.record_execution(50, success=False)

        # Then recover with 100% success (window slides out failures)
        for _ in range(20):
            monitor.record_execution(50, success=True)

        # Should have recovery alert
        recovery_alerts = [
            a for a in alerts
            if a.severity == AlertSeverity.RECOVERED
        ]
        assert len(recovery_alerts) > 0

    def test_no_duplicate_alerts(self, strict_monitor):
        """Test that duplicate alerts are not emitted."""
        alerts = []
        strict_monitor.on_alert(alerts.append)

        # Record multiple failures
        for _ in range(20):
            strict_monitor.record_execution(50, success=False)

        # Should only get one critical alert per SLO type
        availability_critical = [
            a for a in alerts
            if a.slo_type == SLOType.AVAILABILITY
            and a.severity == AlertSeverity.CRITICAL
        ]
        assert len(availability_critical) == 1

    def test_min_samples_requirement(self):
        """Test that alerts are not emitted before min_samples."""
        monitor = SLOMonitor(SLOConfig(min_samples=10))
        alerts = []
        monitor.on_alert(alerts.append)

        # Record fewer than min_samples failures
        for _ in range(5):
            monitor.record_execution(50, success=False)

        # Should not have any alerts yet
        assert len(alerts) == 0

    def test_check_slo(self, monitor):
        """Test checking individual SLOs."""
        for _ in range(10):
            monitor.record_execution(50, success=True)

        healthy, current, threshold = monitor.check_slo(SLOType.AVAILABILITY)

        assert healthy is True
        assert current == 1.0
        assert threshold == 0.999

    def test_reset(self, monitor):
        """Test resetting the monitor."""
        for _ in range(10):
            monitor.record_execution(50, success=True)

        monitor.reset()

        metrics = monitor.get_metrics()
        assert metrics.total_executions == 0

    def test_sliding_window(self):
        """Test that sliding window works correctly."""
        monitor = SLOMonitor(SLOConfig(window_size=5, min_samples=2))

        # Fill the window
        for _ in range(5):
            monitor.record_execution(50, success=True)

        # Add more - should push out old ones
        for _ in range(5):
            monitor.record_execution(50, success=False)

        metrics = monitor.get_metrics()

        # Window should only have the last 5 (all failures)
        assert metrics.total_executions == 5
        assert metrics.failed_executions == 5


class TestSLOAuditSink:
    """Tests for SLOAuditSink."""

    @pytest.fixture
    def monitor(self):
        """Create a monitor."""
        return SLOMonitor(SLOConfig(min_samples=1))

    @pytest.fixture
    def sink(self, monitor):
        """Create an audit sink."""
        return SLOAuditSink(monitor)

    def test_process_successful_event(self, monitor, sink):
        """Test processing a successful audit event."""
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

        sink.record_start("test-123")
        sink.emit(event)

        metrics = monitor.get_metrics()
        assert metrics.total_executions == 1
        assert metrics.successful_executions == 1
        assert metrics.allow_count == 1

    def test_process_failed_event(self, monitor, sink):
        """Test processing a failed audit event."""
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
                agent_id="test-agent",
                version="1.0",
                owner="test",
            ),
            intent=Intent(action="test", reason="testing"),
            tool_request=ToolRequest(
                tool="test:tool",
                action="test",
                resource_type="test",
                effect=Effect.WRITE,
                params={},
            ),
            decision=Decision(
                decision=DecisionType.DENY,
                reason="Denied",
            ),
            outcome=Outcome.BLOCKED,
        )

        sink.emit(event)

        metrics = monitor.get_metrics()
        assert metrics.total_executions == 1
        assert metrics.failed_executions == 1
        assert metrics.deny_count == 1


class TestDecisionRateSLOs:
    """Tests for decision rate SLOs."""

    def test_high_denial_rate_alert(self):
        """Test alert when denial rate is too high."""
        monitor = SLOMonitor(SLOConfig(
            denial_rate_max=0.1,  # 10%
            min_samples=5,
        ))
        alerts = []
        monitor.on_alert(alerts.append)

        # Record decisions with high denial rate
        for _ in range(5):
            monitor.record_decision("ALLOW")
            # Record some executions too
            monitor.record_execution(50, success=True)

        for _ in range(5):
            monitor.record_decision("DENY")
            monitor.record_execution(50, success=True)

        # Should have denial rate alert (50% > 10%)
        denial_alerts = [
            a for a in alerts if a.slo_type == SLOType.DENIAL_RATE
        ]
        assert len(denial_alerts) > 0

    def test_low_approval_rate_alert(self):
        """Test alert when approval rate is too low."""
        monitor = SLOMonitor(SLOConfig(
            approval_rate_min=0.8,  # 80%
            min_samples=5,
        ))
        alerts = []
        monitor.on_alert(alerts.append)

        # Record decisions with low approval rate
        for _ in range(3):
            monitor.record_decision("ALLOW")
            monitor.record_execution(50, success=True)

        for _ in range(7):
            monitor.record_decision("DENY")
            monitor.record_execution(50, success=True)

        # Should have approval rate alert (30% < 80%)
        approval_alerts = [
            a for a in alerts if a.slo_type == SLOType.APPROVAL_RATE
        ]
        assert len(approval_alerts) > 0
