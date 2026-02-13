"""Tests for PolicyPlayground."""

import tempfile
from pathlib import Path

import pytest

from tollgate.playground import PolicyPlayground


@pytest.fixture
def policy_file():
    """Create a temporary policy file."""
    content = """
version: "test-v1"
rules:
  - id: allow_read
    decision: ALLOW
    effect: read
    reason: "Read operations are allowed"

  - id: deny_delete
    decision: DENY
    effect: delete
    reason: "Delete operations are blocked"

  - id: catch_all
    decision: DENY
    reason: "Default deny"
"""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(content)
        f.flush()
        yield Path(f.name)


@pytest.fixture
def playground(policy_file):
    """Create a PolicyPlayground instance."""
    return PolicyPlayground(policy_file)


def test_playground_init(playground, policy_file):
    """Test playground initialization."""
    assert playground.policy_path == policy_file
    assert playground._evaluator is not None
    assert playground._explainer is not None


def test_reset_scenario(playground):
    """Test resetting scenario to defaults."""
    # Modify scenario
    playground._scenario["agent"]["agent_id"] = "modified"

    # Reset
    playground._reset_scenario()

    assert playground._scenario["agent"]["agent_id"] == "test-agent"
    assert playground._scenario["tool_request"]["effect"] == "read"


def test_build_objects(playground):
    """Test building typed objects from scenario."""
    playground._scenario["agent"]["agent_id"] = "my-agent"
    playground._scenario["tool_request"]["tool"] = "api:fetch"
    playground._scenario["tool_request"]["effect"] = "read"

    ctx, intent, req = playground._build_objects()

    assert ctx.agent_id == "my-agent"
    assert req.tool == "api:fetch"
    assert req.effect.value == "read"


def test_build_objects_with_delegation(playground):
    """Test building objects with delegation chain."""
    playground._scenario["agent"]["delegated_by"] = ["parent-agent", "root-agent"]

    ctx, intent, req = playground._build_objects()

    assert ctx.is_delegated
    assert ctx.delegation_depth == 2
    assert ctx.delegated_by == ("parent-agent", "root-agent")


def test_do_set_simple(playground):
    """Test setting a simple field."""
    playground.do_set("agent.agent_id my-custom-agent")

    assert playground._scenario["agent"]["agent_id"] == "my-custom-agent"


def test_do_set_nested(playground):
    """Test setting a nested field."""
    playground.do_set("tool_request.metadata.custom_field test_value")

    assert playground._scenario["tool_request"]["metadata"]["custom_field"] == "test_value"


def test_do_set_json_value(playground):
    """Test setting a JSON value."""
    playground.do_set('agent.delegated_by ["agent-a", "agent-b"]')

    assert playground._scenario["agent"]["delegated_by"] == ["agent-a", "agent-b"]


def test_do_show(playground, capsys):
    """Test showing current scenario."""
    playground.do_show("")

    captured = capsys.readouterr()
    assert "agent_id:" in captured.out
    assert "test-agent" in captured.out


def test_do_eval_allow(playground, capsys):
    """Test evaluating a scenario that should ALLOW."""
    playground._scenario["tool_request"]["effect"] = "read"
    playground._scenario["tool_request"]["manifest_version"] = "1.0.0"

    playground.do_eval("")

    captured = capsys.readouterr()
    assert "ALLOW" in captured.out


def test_do_eval_deny(playground, capsys):
    """Test evaluating a scenario that should DENY."""
    playground._scenario["tool_request"]["effect"] = "delete"
    playground._scenario["tool_request"]["manifest_version"] = "1.0.0"

    playground.do_eval("")

    captured = capsys.readouterr()
    assert "DENY" in captured.out


def test_do_explain(playground, capsys):
    """Test explaining a scenario."""
    playground._scenario["tool_request"]["effect"] = "read"
    playground._scenario["tool_request"]["manifest_version"] = "1.0.0"

    playground.do_explain("")

    captured = capsys.readouterr()
    assert "DECISION EXPLANATION" in captured.out
    assert "FINAL DECISION" in captured.out


def test_do_rules(playground, capsys):
    """Test showing policy rules."""
    playground.do_rules("")

    captured = capsys.readouterr()
    assert "allow_read" in captured.out
    assert "deny_delete" in captured.out
    assert "catch_all" in captured.out


def test_do_reset(playground, capsys):
    """Test reset command."""
    playground._scenario["agent"]["agent_id"] = "modified"

    playground.do_reset("")

    captured = capsys.readouterr()
    assert "reset to defaults" in captured.out
    assert playground._scenario["agent"]["agent_id"] == "test-agent"


def test_do_reload(playground, capsys):
    """Test reload command."""
    playground.do_reload("")

    captured = capsys.readouterr()
    assert "Loaded policy" in captured.out


def test_do_quit(playground):
    """Test quit command."""
    result = playground.do_quit("")
    assert result is True


def test_do_exit(playground):
    """Test exit command (alias for quit)."""
    result = playground.do_exit("")
    assert result is True


def test_save_and_load(playground, tmp_path, capsys):
    """Test saving and loading scenarios."""
    # Set custom values
    playground._scenario["agent"]["agent_id"] = "saved-agent"
    playground._scenario["tool_request"]["tool"] = "saved:tool"

    # Save
    save_path = tmp_path / "scenario.yaml"
    playground.do_save(str(save_path))

    # Reset
    playground.do_reset("")
    assert playground._scenario["agent"]["agent_id"] == "test-agent"

    # Load
    playground.do_load(str(save_path))

    assert playground._scenario["agent"]["agent_id"] == "saved-agent"
    assert playground._scenario["tool_request"]["tool"] == "saved:tool"


def test_batch_testing(playground, tmp_path, capsys):
    """Test batch scenario testing."""
    scenarios_content = """
scenarios:
  - name: "Test read allowed"
    tool_request:
      tool: api:fetch
      effect: read
      manifest_version: "1.0.0"
    expected:
      decision: ALLOW

  - name: "Test delete denied"
    tool_request:
      tool: api:delete
      effect: delete
      manifest_version: "1.0.0"
    expected:
      decision: DENY
"""
    scenarios_file = tmp_path / "scenarios.yaml"
    scenarios_file.write_text(scenarios_content)

    playground.do_batch(str(scenarios_file))

    captured = capsys.readouterr()
    assert "[PASS]" in captured.out
    assert "Test read allowed" in captured.out
    assert "Test delete denied" in captured.out


def test_auto_reload(policy_file, capsys):
    """Test auto-reload when policy file changes."""
    playground = PolicyPlayground(policy_file, auto_reload=True)
    initial_mtime = playground._policy_mtime

    # Simulate file change by touching
    import time
    time.sleep(0.1)
    policy_file.touch()

    # precmd should detect change
    playground.precmd("show")

    captured = capsys.readouterr()
    assert "reloading" in captured.out.lower() or playground._policy_mtime > initial_mtime
