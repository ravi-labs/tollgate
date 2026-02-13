"""Tests for Audit Log Viewer CLI."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from tollgate.audit_viewer import (
    AuditFilter,
    AuditLogReader,
    format_event,
    format_stats,
)


@pytest.fixture
def audit_log_file():
    """Create a temporary audit log file."""
    events = [
        {
            "schema_version": "1.0",
            "timestamp": "2024-01-15T10:00:00Z",
            "correlation_id": "corr-001",
            "request_hash": "hash-001",
            "agent": {
                "agent_id": "agent-1",
                "version": "1.0",
                "owner": "user-1",
                "metadata": {"org_id": "org-a"},
            },
            "intent": {"action": "fetch", "reason": "user request"},
            "tool_request": {
                "tool": "api:fetch",
                "action": "get",
                "resource_type": "url",
                "effect": "read",
            },
            "decision": {"decision": "ALLOW", "reason": "Rule matched"},
            "outcome": "executed",
        },
        {
            "schema_version": "1.0",
            "timestamp": "2024-01-15T10:05:00Z",
            "correlation_id": "corr-002",
            "request_hash": "hash-002",
            "agent": {
                "agent_id": "agent-2",
                "version": "1.0",
                "owner": "user-2",
                "metadata": {"org_id": "org-b"},
            },
            "intent": {"action": "delete", "reason": "cleanup"},
            "tool_request": {
                "tool": "api:delete",
                "action": "remove",
                "resource_type": "file",
                "effect": "delete",
            },
            "decision": {"decision": "DENY", "reason": "Not allowed"},
            "outcome": "blocked",
        },
        {
            "schema_version": "1.0",
            "timestamp": "2024-01-15T10:10:00Z",
            "correlation_id": "corr-003",
            "request_hash": "hash-003",
            "agent": {
                "agent_id": "agent-1",
                "version": "1.0",
                "owner": "user-1",
                "metadata": {"org_id": "org-a"},
            },
            "intent": {"action": "write", "reason": "save data"},
            "tool_request": {
                "tool": "api:write",
                "action": "put",
                "resource_type": "record",
                "effect": "write",
            },
            "decision": {"decision": "ASK", "reason": "Needs approval"},
            "outcome": "executed",
            "approval_id": "approval-001",
        },
    ]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False
    ) as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
        f.flush()
        yield Path(f.name)


@pytest.fixture
def reader(audit_log_file):
    """Create an AuditLogReader instance."""
    return AuditLogReader(audit_log_file)


class TestAuditFilter:
    """Tests for AuditFilter."""

    def test_no_filter_matches_all(self):
        """Test that empty filter matches all events."""
        filter_ = AuditFilter()
        event = {"agent": {"agent_id": "any"}, "outcome": "any"}
        assert filter_.matches(event)

    def test_filter_by_agent_id(self):
        """Test filtering by agent ID."""
        filter_ = AuditFilter(agent_id="agent-1")

        event1 = {"agent": {"agent_id": "agent-1"}}
        event2 = {"agent": {"agent_id": "agent-2"}}

        assert filter_.matches(event1)
        assert not filter_.matches(event2)

    def test_filter_by_tool(self):
        """Test filtering by tool (prefix match)."""
        filter_ = AuditFilter(tool="api:")

        event1 = {"tool_request": {"tool": "api:fetch"}}
        event2 = {"tool_request": {"tool": "mcp:tool"}}

        assert filter_.matches(event1)
        assert not filter_.matches(event2)

    def test_filter_by_outcome(self):
        """Test filtering by outcome."""
        filter_ = AuditFilter(outcome="blocked")

        event1 = {"outcome": "blocked"}
        event2 = {"outcome": "executed"}

        assert filter_.matches(event1)
        assert not filter_.matches(event2)

    def test_filter_by_decision(self):
        """Test filtering by decision."""
        filter_ = AuditFilter(decision="DENY")

        event1 = {"decision": {"decision": "DENY"}}
        event2 = {"decision": {"decision": "ALLOW"}}

        assert filter_.matches(event1)
        assert not filter_.matches(event2)

    def test_filter_by_org_id(self):
        """Test filtering by org ID."""
        filter_ = AuditFilter(org_id="org-a")

        event1 = {"agent": {"metadata": {"org_id": "org-a"}}}
        event2 = {"agent": {"metadata": {"org_id": "org-b"}}}

        assert filter_.matches(event1)
        assert not filter_.matches(event2)

    def test_filter_by_time_range(self):
        """Test filtering by time range."""
        filter_ = AuditFilter(
            since=datetime(2024, 1, 15, 10, 0, 0),
            until=datetime(2024, 1, 15, 10, 8, 0),
        )

        event1 = {"timestamp": "2024-01-15T10:05:00Z"}  # In range
        event2 = {"timestamp": "2024-01-15T10:10:00Z"}  # After range
        event3 = {"timestamp": "2024-01-15T09:55:00Z"}  # Before range

        assert filter_.matches(event1)
        assert not filter_.matches(event2)
        assert not filter_.matches(event3)

    def test_filter_combined(self):
        """Test combining multiple filters."""
        filter_ = AuditFilter(
            agent_id="agent-1",
            outcome="executed",
        )

        event1 = {"agent": {"agent_id": "agent-1"}, "outcome": "executed"}
        event2 = {"agent": {"agent_id": "agent-1"}, "outcome": "blocked"}
        event3 = {"agent": {"agent_id": "agent-2"}, "outcome": "executed"}

        assert filter_.matches(event1)
        assert not filter_.matches(event2)
        assert not filter_.matches(event3)


class TestAuditLogReader:
    """Tests for AuditLogReader."""

    def test_read_all_events(self, reader):
        """Test reading all events."""
        events = list(reader.read_events())
        assert len(events) == 3

    def test_read_with_limit(self, reader):
        """Test reading with a limit."""
        events = list(reader.read_events(limit=2))
        assert len(events) == 2

    def test_read_reversed(self, reader):
        """Test reading in reverse order."""
        events = list(reader.read_events(reverse=True))

        assert len(events) == 3
        # Most recent first
        assert events[0]["correlation_id"] == "corr-003"
        assert events[2]["correlation_id"] == "corr-001"

    def test_read_with_filter(self, reader):
        """Test reading with filter."""
        filter_ = AuditFilter(agent_id="agent-1")
        events = list(reader.read_events(filter_=filter_))

        assert len(events) == 2
        assert all(e["agent"]["agent_id"] == "agent-1" for e in events)

    def test_get_stats(self, reader):
        """Test getting statistics."""
        stats = reader.get_stats()

        assert stats["total_events"] == 3
        assert stats["outcomes"]["executed"] == 2
        assert stats["outcomes"]["blocked"] == 1
        assert stats["decisions"]["ALLOW"] == 1
        assert stats["decisions"]["DENY"] == 1
        assert stats["decisions"]["ASK"] == 1
        assert "agent-1" in stats["top_agents"]
        assert stats["top_agents"]["agent-1"] == 2

    def test_get_stats_with_filter(self, reader):
        """Test getting statistics with filter."""
        filter_ = AuditFilter(agent_id="agent-1")
        stats = reader.get_stats(filter_=filter_)

        assert stats["total_events"] == 2

    def test_file_not_found(self):
        """Test handling of missing file."""
        with pytest.raises(FileNotFoundError):
            AuditLogReader("/nonexistent/path.jsonl")


class TestFormatFunctions:
    """Tests for formatting functions."""

    def test_format_event_basic(self):
        """Test basic event formatting."""
        event = {
            "timestamp": "2024-01-15T10:00:00Z",
            "outcome": "executed",
            "agent": {"agent_id": "agent-1"},
            "tool_request": {"tool": "api:fetch", "action": "get", "effect": "read"},
        }

        output = format_event(event)

        assert "2024-01-15T10:00:00Z" in output
        assert "executed" in output
        assert "agent-1" in output
        assert "api:fetch" in output

    def test_format_event_verbose(self):
        """Test verbose event formatting."""
        event = {
            "timestamp": "2024-01-15T10:00:00Z",
            "outcome": "executed",
            "correlation_id": "corr-001",
            "agent": {"agent_id": "agent-1"},
            "tool_request": {"tool": "api:fetch", "action": "get", "effect": "read"},
            "decision": {"decision": "ALLOW", "reason": "Rule matched"},
            "grant_id": "grant-001",
        }

        output = format_event(event, verbose=True)

        assert "Correlation ID: corr-001" in output
        assert "Decision: ALLOW" in output
        assert "Grant ID: grant-001" in output

    def test_format_stats(self):
        """Test statistics formatting."""
        stats = {
            "total_events": 100,
            "time_range": {
                "first": "2024-01-15T10:00:00Z",
                "last": "2024-01-15T12:00:00Z",
            },
            "outcomes": {"executed": 80, "blocked": 20},
            "decisions": {"ALLOW": 70, "DENY": 20, "ASK": 10},
            "effects": {"read": 60, "write": 30, "delete": 10},
            "top_tools": {"api:fetch": 50, "api:write": 30},
            "top_agents": {"agent-1": 60, "agent-2": 40},
        }

        output = format_stats(stats)

        assert "AUDIT LOG STATISTICS" in output
        assert "Total Events: 100" in output
        assert "executed" in output
        assert "80" in output
        assert "agent-1" in output


class TestCLI:
    """Tests for CLI entry point."""

    def test_cli_logs(self, audit_log_file):
        """Test CLI logs command."""
        from tollgate.audit_viewer import cli_main

        result = cli_main(["logs", str(audit_log_file), "--limit", "2"])
        assert result == 0

    def test_cli_logs_json(self, audit_log_file, capsys):
        """Test CLI logs with JSON output."""
        from tollgate.audit_viewer import cli_main

        result = cli_main(["logs", str(audit_log_file), "--json"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert result == 0
        assert len(data) == 3

    def test_cli_stats(self, audit_log_file, capsys):
        """Test CLI stats command."""
        from tollgate.audit_viewer import cli_main

        result = cli_main(["stats", str(audit_log_file)])

        captured = capsys.readouterr()
        assert result == 0
        assert "AUDIT LOG STATISTICS" in captured.out

    def test_cli_stats_json(self, audit_log_file, capsys):
        """Test CLI stats with JSON output."""
        from tollgate.audit_viewer import cli_main

        result = cli_main(["stats", str(audit_log_file), "--json"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert result == 0
        assert "total_events" in data

    def test_cli_missing_file(self, capsys):
        """Test CLI with missing file."""
        from tollgate.audit_viewer import cli_main

        result = cli_main(["logs", "/nonexistent/path.jsonl"])
        assert result == 1

    def test_cli_filter_options(self, audit_log_file):
        """Test CLI with filter options."""
        from tollgate.audit_viewer import cli_main

        result = cli_main([
            "logs", str(audit_log_file),
            "--agent", "agent-1",
            "--outcome", "executed",
        ])
        assert result == 0
