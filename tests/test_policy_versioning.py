"""Tests for Policy Versioning & Rollback."""

import pytest

from tollgate.policy_versioning import (
    InMemoryPolicyVersionStore,
    PolicyDiff,
    PolicyVersion,
    SQLitePolicyVersionStore,
)

POLICY_V1 = """
version: "v1"
defaults:
  decision: DENY
rules:
  - id: allow_read
    decision: ALLOW
    effect: read
"""

POLICY_V2 = """
version: "v2"
defaults:
  decision: DENY
rules:
  - id: allow_read
    decision: ALLOW
    effect: read
  - id: allow_write
    decision: ASK
    effect: write
"""

POLICY_V3 = """
version: "v3"
defaults:
  decision: ASK
rules:
  - id: allow_read
    decision: ALLOW
    effect: read
  - id: allow_write
    decision: ALLOW
    effect: write
"""


class TestPolicyVersion:
    """Tests for PolicyVersion dataclass."""

    def test_to_dict(self):
        """Test converting to dictionary."""
        version = PolicyVersion(
            id="abc123",
            version_number=1,
            content_hash="hash123",
            content="content",
            author="admin",
            message="Initial version",
            created_at=1234567890.0,
            parent_id=None,
            metadata={"key": "value"},
            is_active=True,
        )

        d = version.to_dict()

        assert d["id"] == "abc123"
        assert d["version_number"] == 1
        assert d["is_active"] is True
        assert d["metadata"] == {"key": "value"}

    def test_from_dict(self):
        """Test creating from dictionary."""
        d = {
            "id": "abc123",
            "version_number": 1,
            "content_hash": "hash123",
            "content": "content",
            "author": "admin",
            "message": "Initial version",
            "created_at": 1234567890.0,
            "parent_id": None,
            "metadata": {},
            "is_active": True,
        }

        version = PolicyVersion.from_dict(d)

        assert version.id == "abc123"
        assert version.version_number == 1
        assert version.is_active is True


class TestInMemoryPolicyVersionStore:
    """Tests for InMemoryPolicyVersionStore."""

    @pytest.fixture
    def store(self):
        """Create an in-memory store."""
        return InMemoryPolicyVersionStore()

    @pytest.mark.asyncio
    async def test_save_first_version(self, store):
        """Test saving the first version."""
        version_id = await store.save_version(
            content=POLICY_V1,
            author="admin",
            message="Initial policy",
        )

        assert version_id is not None
        assert len(version_id) == 16

    @pytest.mark.asyncio
    async def test_get_version(self, store):
        """Test getting a specific version."""
        version_id = await store.save_version(
            content=POLICY_V1,
            author="admin",
            message="Initial policy",
        )

        version = await store.get_version(version_id)

        assert version is not None
        assert version.id == version_id
        assert version.version_number == 1
        assert version.author == "admin"
        assert version.message == "Initial policy"
        assert version.is_active is True

    @pytest.mark.asyncio
    async def test_get_nonexistent_version(self, store):
        """Test getting a nonexistent version."""
        version = await store.get_version("nonexistent")

        assert version is None

    @pytest.mark.asyncio
    async def test_get_active_version(self, store):
        """Test getting the active version."""
        await store.save_version(POLICY_V1, "admin", "v1")
        await store.save_version(POLICY_V2, "admin", "v2")

        active = await store.get_active_version()

        assert active is not None
        assert active.version_number == 2
        assert "v2" in active.content

    @pytest.mark.asyncio
    async def test_version_numbers_increment(self, store):
        """Test that version numbers increment correctly."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        v2_id = await store.save_version(POLICY_V2, "admin", "v2")
        v3_id = await store.save_version(POLICY_V3, "admin", "v3")

        v1 = await store.get_version(v1_id)
        v2 = await store.get_version(v2_id)
        v3 = await store.get_version(v3_id)

        assert v1.version_number == 1
        assert v2.version_number == 2
        assert v3.version_number == 3

    @pytest.mark.asyncio
    async def test_parent_chain(self, store):
        """Test that parent references are set correctly."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        v2_id = await store.save_version(POLICY_V2, "admin", "v2")

        v1 = await store.get_version(v1_id)
        v2 = await store.get_version(v2_id)

        assert v1.parent_id is None
        assert v2.parent_id == v1_id

    @pytest.mark.asyncio
    async def test_duplicate_content_returns_existing(self, store):
        """Test that saving duplicate content returns existing version."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        v2_id = await store.save_version(POLICY_V1, "admin", "same content")

        assert v1_id == v2_id

    @pytest.mark.asyncio
    async def test_list_versions(self, store):
        """Test listing versions."""
        await store.save_version(POLICY_V1, "admin", "v1")
        await store.save_version(POLICY_V2, "admin", "v2")
        await store.save_version(POLICY_V3, "admin", "v3")

        versions = await store.list_versions()

        assert len(versions) == 3
        # Should be in reverse chronological order
        assert versions[0].version_number == 3
        assert versions[1].version_number == 2
        assert versions[2].version_number == 1

    @pytest.mark.asyncio
    async def test_list_versions_with_limit(self, store):
        """Test listing versions with limit."""
        await store.save_version(POLICY_V1, "admin", "v1")
        await store.save_version(POLICY_V2, "admin", "v2")
        await store.save_version(POLICY_V3, "admin", "v3")

        versions = await store.list_versions(limit=2)

        assert len(versions) == 2
        assert versions[0].version_number == 3
        assert versions[1].version_number == 2

    @pytest.mark.asyncio
    async def test_list_versions_with_offset(self, store):
        """Test listing versions with offset."""
        await store.save_version(POLICY_V1, "admin", "v1")
        await store.save_version(POLICY_V2, "admin", "v2")
        await store.save_version(POLICY_V3, "admin", "v3")

        versions = await store.list_versions(limit=10, offset=1)

        assert len(versions) == 2
        assert versions[0].version_number == 2
        assert versions[1].version_number == 1

    @pytest.mark.asyncio
    async def test_rollback(self, store):
        """Test rolling back to a previous version."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        await store.save_version(POLICY_V2, "admin", "v2")

        rollback_id = await store.rollback(v1_id, "admin")

        # Rollback creates a new version
        rollback = await store.get_version(rollback_id)
        assert rollback.version_number == 3
        assert "Rollback" in rollback.message
        assert "v1" in rollback.content

    @pytest.mark.asyncio
    async def test_rollback_nonexistent_version(self, store):
        """Test rolling back to a nonexistent version."""
        with pytest.raises(ValueError, match="not found"):
            await store.rollback("nonexistent", "admin")

    @pytest.mark.asyncio
    async def test_diff_versions_added_rule(self, store):
        """Test diffing versions with added rules."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        v2_id = await store.save_version(POLICY_V2, "admin", "v2")

        diff = await store.diff_versions(v1_id, v2_id)

        assert isinstance(diff, PolicyDiff)
        assert len(diff.added_rules) == 1
        assert diff.added_rules[0]["id"] == "allow_write"
        assert len(diff.removed_rules) == 0
        assert diff.version_changed is True

    @pytest.mark.asyncio
    async def test_diff_versions_modified_rule(self, store):
        """Test diffing versions with modified rules."""
        v2_id = await store.save_version(POLICY_V2, "admin", "v2")
        v3_id = await store.save_version(POLICY_V3, "admin", "v3")

        diff = await store.diff_versions(v2_id, v3_id)

        assert len(diff.modified_rules) == 1
        assert diff.modified_rules[0]["id"] == "allow_write"
        assert diff.defaults_changed is True

    @pytest.mark.asyncio
    async def test_diff_summary(self, store):
        """Test diff summary generation."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        v2_id = await store.save_version(POLICY_V2, "admin", "v2")

        diff = await store.diff_versions(v1_id, v2_id)

        assert "version:" in diff.summary
        assert "+1 rules" in diff.summary

    @pytest.mark.asyncio
    async def test_metadata_preserved(self, store):
        """Test that metadata is preserved."""
        version_id = await store.save_version(
            content=POLICY_V1,
            author="admin",
            message="With metadata",
            metadata={"env": "production", "approved_by": "security"},
        )

        version = await store.get_version(version_id)

        assert version.metadata["env"] == "production"
        assert version.metadata["approved_by"] == "security"


class TestSQLitePolicyVersionStore:
    """Tests for SQLitePolicyVersionStore."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a SQLite store."""
        db_path = tmp_path / "policies.db"
        return SQLitePolicyVersionStore(db_path)

    @pytest.mark.asyncio
    async def test_save_and_get_version(self, store):
        """Test saving and getting a version."""
        version_id = await store.save_version(
            content=POLICY_V1,
            author="admin",
            message="Initial policy",
        )

        version = await store.get_version(version_id)

        assert version is not None
        assert version.id == version_id
        assert version.version_number == 1
        assert version.is_active is True

    @pytest.mark.asyncio
    async def test_active_version_tracking(self, store):
        """Test that active version is tracked correctly."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        v2_id = await store.save_version(POLICY_V2, "admin", "v2")

        v1 = await store.get_version(v1_id)
        v2 = await store.get_version(v2_id)
        active = await store.get_active_version()

        assert v1.is_active is False
        assert v2.is_active is True
        assert active.id == v2_id

    @pytest.mark.asyncio
    async def test_version_count(self, store):
        """Test getting version count."""
        await store.save_version(POLICY_V1, "admin", "v1")
        await store.save_version(POLICY_V2, "admin", "v2")

        count = await store.get_version_count()

        assert count == 2

    @pytest.mark.asyncio
    async def test_version_history(self, store):
        """Test getting version history."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        await store.save_version(POLICY_V2, "admin", "v2")
        v3_id = await store.save_version(POLICY_V3, "admin", "v3")

        history = await store.get_version_history(v3_id, depth=10)

        assert len(history) == 3
        assert history[0].id == v3_id
        assert history[2].id == v1_id

    @pytest.mark.asyncio
    async def test_rollback_creates_new_version(self, store):
        """Test that rollback creates a new version."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        await store.save_version(POLICY_V2, "admin", "v2")

        initial_count = await store.get_version_count()

        await store.rollback(v1_id, "admin")

        final_count = await store.get_version_count()
        assert final_count == initial_count + 1

    @pytest.mark.asyncio
    async def test_diff_versions(self, store):
        """Test diffing versions."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        v2_id = await store.save_version(POLICY_V2, "admin", "v2")

        diff = await store.diff_versions(v1_id, v2_id)

        assert len(diff.added_rules) == 1
        assert diff.version_changed is True

    @pytest.mark.asyncio
    async def test_duplicate_content_detection(self, store):
        """Test that duplicate content is detected."""
        v1_id = await store.save_version(POLICY_V1, "admin", "v1")
        v2_id = await store.save_version(POLICY_V1, "admin", "duplicate")

        # Should return the same ID
        assert v1_id == v2_id

        count = await store.get_version_count()
        assert count == 1


class TestVersionedPolicyEvaluator:
    """Tests for VersionedPolicyEvaluator."""

    @pytest.mark.asyncio
    async def test_create_evaluator(self, tmp_path):
        """Test creating a versioned evaluator."""
        from tollgate.policy_versioning import VersionedPolicyEvaluator

        db_path = tmp_path / "policies.db"
        store = SQLitePolicyVersionStore(db_path)

        # Save a version first
        await store.save_version(POLICY_V1, "admin", "v1")

        # Create evaluator
        evaluator = await VersionedPolicyEvaluator.create(store)

        assert evaluator.version_number == 1

    @pytest.mark.asyncio
    async def test_reload_when_changed(self, tmp_path):
        """Test reloading when version changes."""
        from tollgate.policy_versioning import VersionedPolicyEvaluator

        db_path = tmp_path / "policies.db"
        store = SQLitePolicyVersionStore(db_path)

        # Save first version
        await store.save_version(POLICY_V1, "admin", "v1")

        # Create evaluator
        evaluator = await VersionedPolicyEvaluator.create(store)
        assert evaluator.version_number == 1

        # Save new version
        await store.save_version(POLICY_V2, "admin", "v2")

        # Reload
        reloaded = await evaluator.reload()

        assert reloaded is True
        assert evaluator.version_number == 2

    @pytest.mark.asyncio
    async def test_reload_when_unchanged(self, tmp_path):
        """Test reload returns False when no change."""
        from tollgate.policy_versioning import VersionedPolicyEvaluator

        db_path = tmp_path / "policies.db"
        store = SQLitePolicyVersionStore(db_path)

        await store.save_version(POLICY_V1, "admin", "v1")

        evaluator = await VersionedPolicyEvaluator.create(store)

        reloaded = await evaluator.reload()

        assert reloaded is False

    @pytest.mark.asyncio
    async def test_no_active_version_raises(self, tmp_path):
        """Test that creating evaluator without active version raises."""
        from tollgate.policy_versioning import VersionedPolicyEvaluator

        db_path = tmp_path / "policies.db"
        store = SQLitePolicyVersionStore(db_path)

        # Don't save any version

        with pytest.raises(ValueError, match="No active policy"):
            await VersionedPolicyEvaluator.create(store)
