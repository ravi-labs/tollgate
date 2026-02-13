"""Tests for CLI commands."""

import json

from tollgate.cli import (
    grant_command,
    health_command,
    main,
    policy_command,
)


class TestPolicyValidate:
    """Tests for policy validate command."""

    def test_validate_valid_policy(self, capsys, tmp_path):
        """Test validating a valid policy."""
        policy_content = """
version: "test-v1"
rules:
  - id: allow_read
    decision: ALLOW
    effect: read
    reason: "Read allowed"
"""
        policy_file = tmp_path / "valid_policy.yaml"
        policy_file.write_text(policy_content)

        result = policy_command(["validate", str(policy_file)])

        assert result == 0
        captured = capsys.readouterr()
        assert "Policy file is valid" in captured.out

    def test_validate_verbose(self, capsys, tmp_path):
        """Test verbose validation output."""
        policy_content = """
version: "test-v1"
defaults:
  decision: DENY
rules:
  - id: allow_read
    decision: ALLOW
    effect: read
  - id: deny_write
    decision: DENY
    effect: write
"""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(policy_content)

        result = policy_command(["validate", str(policy_file), "-v"])

        assert result == 0
        captured = capsys.readouterr()
        assert "Version: test-v1" in captured.out
        assert "Rules: 2" in captured.out
        assert "allow_read" in captured.out
        assert "deny_write" in captured.out

    def test_validate_nonexistent_file(self, capsys):
        """Test validating a nonexistent file."""
        result = policy_command(["validate", "/nonexistent/path.yaml"])

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_validate_invalid_yaml(self, capsys, tmp_path):
        """Test validating invalid YAML."""
        policy_file = tmp_path / "invalid.yaml"
        policy_file.write_text("this: is: not: valid: yaml: {{{}}")

        result = policy_command(["validate", str(policy_file)])

        assert result == 1
        captured = capsys.readouterr()
        assert "validation failed" in captured.out


class TestPolicyDiff:
    """Tests for policy diff command."""

    def test_diff_no_changes(self, capsys, tmp_path):
        """Test diff with identical policies."""
        policy_content = """
version: "v1"
rules:
  - id: rule1
    decision: ALLOW
"""
        old_file = tmp_path / "old.yaml"
        new_file = tmp_path / "new.yaml"
        old_file.write_text(policy_content)
        new_file.write_text(policy_content)

        result = policy_command(["diff", str(old_file), str(new_file)])

        assert result == 0
        captured = capsys.readouterr()
        assert "No differences found" in captured.out

    def test_diff_version_change(self, capsys, tmp_path):
        """Test diff with version change."""
        old_file = tmp_path / "old.yaml"
        new_file = tmp_path / "new.yaml"
        old_file.write_text("version: v1\nrules: []")
        new_file.write_text("version: v2\nrules: []")

        result = policy_command(["diff", str(old_file), str(new_file)])

        assert result == 0
        captured = capsys.readouterr()
        assert "v1" in captured.out
        assert "v2" in captured.out

    def test_diff_rule_added(self, capsys, tmp_path):
        """Test diff with added rule."""
        old_content = """
version: v1
rules:
  - id: rule1
    decision: ALLOW
"""
        new_content = """
version: v1
rules:
  - id: rule1
    decision: ALLOW
  - id: rule2
    decision: DENY
"""
        old_file = tmp_path / "old.yaml"
        new_file = tmp_path / "new.yaml"
        old_file.write_text(old_content)
        new_file.write_text(new_content)

        result = policy_command(["diff", str(old_file), str(new_file)])

        assert result == 0
        captured = capsys.readouterr()
        assert "Added rules" in captured.out
        assert "rule2" in captured.out

    def test_diff_rule_removed(self, capsys, tmp_path):
        """Test diff with removed rule."""
        old_content = """
version: v1
rules:
  - id: rule1
    decision: ALLOW
  - id: rule2
    decision: DENY
"""
        new_content = """
version: v1
rules:
  - id: rule1
    decision: ALLOW
"""
        old_file = tmp_path / "old.yaml"
        new_file = tmp_path / "new.yaml"
        old_file.write_text(old_content)
        new_file.write_text(new_content)

        result = policy_command(["diff", str(old_file), str(new_file)])

        assert result == 0
        captured = capsys.readouterr()
        assert "Removed rules" in captured.out
        assert "rule2" in captured.out

    def test_diff_rule_modified(self, capsys, tmp_path):
        """Test diff with modified rule."""
        old_content = """
version: v1
rules:
  - id: rule1
    decision: ALLOW
"""
        new_content = """
version: v1
rules:
  - id: rule1
    decision: DENY
"""
        old_file = tmp_path / "old.yaml"
        new_file = tmp_path / "new.yaml"
        old_file.write_text(old_content)
        new_file.write_text(new_content)

        result = policy_command(["diff", str(old_file), str(new_file)])

        assert result == 0
        captured = capsys.readouterr()
        assert "Modified rules" in captured.out
        assert "rule1" in captured.out
        assert "ALLOW" in captured.out
        assert "DENY" in captured.out


class TestGrantCommands:
    """Tests for grant CLI commands."""

    def test_grant_help(self, capsys):
        """Test grant help."""
        result = grant_command(["--help"])

        assert result == 0
        captured = capsys.readouterr()
        assert "list" in captured.out
        assert "create" in captured.out
        assert "revoke" in captured.out

    def test_grant_list_empty(self, capsys, tmp_path):
        """Test listing grants from empty store."""
        db_path = tmp_path / "grants.db"

        result = grant_command(["list", "--store", str(db_path)])

        assert result == 0
        captured = capsys.readouterr()
        assert "No active grants found" in captured.out

    def test_grant_create_and_list(self, capsys, tmp_path):
        """Test creating and listing a grant."""
        db_path = tmp_path / "grants.db"

        # Create a grant
        result = grant_command([
            "create",
            "--agent", "test-agent",
            "--tool", "api:fetch",
            "--effect", "read",
            "--store", str(db_path),
        ])

        assert result == 0
        captured = capsys.readouterr()
        assert "Created grant" in captured.out

        # List grants
        result = grant_command(["list", "--store", str(db_path)])

        assert result == 0
        captured = capsys.readouterr()
        assert "test-agent" in captured.out
        assert "api:fetch" in captured.out

    def test_grant_list_json(self, capsys, tmp_path):
        """Test listing grants as JSON."""
        db_path = tmp_path / "grants.db"

        # Create a grant first
        grant_command([
            "create",
            "--agent", "test-agent",
            "--tool", "api:*",
            "--effect", "read",
            "--store", str(db_path),
        ])

        # Clear the output from create
        capsys.readouterr()

        # List as JSON
        result = grant_command(["list", "--json", "--store", str(db_path)])

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert len(output) == 1
        assert output[0]["agent_id"] == "test-agent"

    def test_grant_revoke(self, capsys, tmp_path):
        """Test revoking a grant."""
        db_path = tmp_path / "grants.db"

        # Create a grant
        grant_command([
            "create",
            "--agent", "test-agent",
            "--tool", "api:fetch",
            "--effect", "read",
            "--store", str(db_path),
        ])

        # Get the grant ID from list --json
        capsys.readouterr()  # Clear previous output
        grant_command(["list", "--json", "--store", str(db_path)])
        captured = capsys.readouterr()
        grants = json.loads(captured.out)
        grant_id = grants[0]["id"]

        # Revoke it
        result = grant_command(["revoke", grant_id, "--store", str(db_path)])

        assert result == 0
        captured = capsys.readouterr()
        assert "Revoked grant" in captured.out

        # Verify it's gone
        result = grant_command(["list", "--store", str(db_path)])
        captured = capsys.readouterr()
        assert "No active grants found" in captured.out


class TestHealthCommand:
    """Tests for health command."""

    def test_health_basic(self, capsys):
        """Test basic health check."""
        result = health_command([])

        assert result == 0
        captured = capsys.readouterr()
        assert "Tollgate Health Check" in captured.out
        assert "Version" in captured.out
        assert "Policy Engine" in captured.out

    def test_health_json(self, capsys):
        """Test health check JSON output."""
        result = health_command(["--json"])

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)

        assert "version" in output
        assert "policy_engine" in output
        assert output["version"]["status"] == "ok"

    def test_health_with_store(self, capsys, tmp_path):
        """Test health check with store."""
        db_path = tmp_path / "grants.db"

        # Create the store first
        import asyncio

        from tollgate.backends.sqlite_store import SQLiteGrantStore

        async def _init():
            store = SQLiteGrantStore(str(db_path))
            await store.list_active_grants()

        asyncio.run(_init())

        result = health_command(["--store", str(db_path)])

        assert result == 0
        captured = capsys.readouterr()
        assert "Grant Store" in captured.out
        assert "0 active grants" in captured.out


class TestMainEntryPoint:
    """Tests for main CLI entry point."""

    def test_main_help(self, capsys):
        """Test main help."""
        result = main(["--help"])

        assert result == 0
        captured = capsys.readouterr()
        assert "tollgate" in captured.out.lower()
        assert "policy" in captured.out
        assert "grant" in captured.out
        assert "health" in captured.out

    def test_main_version(self, capsys):
        """Test main version."""
        result = main(["--version"])

        assert result == 0
        captured = capsys.readouterr()
        assert "tollgate" in captured.out

    def test_main_unknown_command(self, capsys):
        """Test unknown command."""
        result = main(["unknown-command"])

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown command" in captured.out

    def test_main_policy_subcommand(self, tmp_path, capsys):
        """Test policy subcommand via main."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("version: test\nrules: []")

        result = main(["policy", "validate", str(policy_file)])

        assert result == 0
        captured = capsys.readouterr()
        assert "valid" in captured.out

    def test_main_health_subcommand(self, capsys):
        """Test health subcommand via main."""
        result = main(["health"])

        assert result == 0
        captured = capsys.readouterr()
        assert "Health Check" in captured.out
