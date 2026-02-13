"""Tests for the REST API."""

import time

import pytest

# Skip if FastAPI not installed
fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from tollgate import Effect, Grant, InMemoryApprovalStore, InMemoryGrantStore
from tollgate.api import create_app


@pytest.fixture
def grant_store():
    return InMemoryGrantStore()


@pytest.fixture
def approval_store():
    return InMemoryApprovalStore()


@pytest.fixture
def client(grant_store, approval_store):
    app = create_app(
        grant_store=grant_store,
        approval_store=approval_store,
    )
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_includes_status(self, client):
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "healthy"

    def test_health_shows_configured_stores(self, client):
        response = client.get("/health")
        data = response.json()
        assert data["stores"]["grants"] is True
        assert data["stores"]["approvals"] is True
        assert data["stores"]["audit"] is False  # Not configured in fixture


class TestGrantsEndpoint:
    def test_list_grants_empty(self, client):
        response = client.get("/api/v1/grants")
        assert response.status_code == 200
        data = response.json()
        assert data["grants"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_list_grants_with_data(self, client, grant_store):
        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="test_tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
        )
        await grant_store.create_grant(grant)

        response = client.get("/api/v1/grants")
        assert response.status_code == 200
        data = response.json()
        assert len(data["grants"]) == 1
        assert data["grants"][0]["agent_id"] == "agent-1"
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_list_grants_filter_by_agent_id(self, client, grant_store):
        g1 = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
        )
        g2 = Grant(
            agent_id="agent-2",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
        )
        await grant_store.create_grant(g1)
        await grant_store.create_grant(g2)

        response = client.get("/api/v1/grants?agent_id=agent-1")
        assert response.status_code == 200
        data = response.json()
        assert len(data["grants"]) == 1
        assert data["grants"][0]["agent_id"] == "agent-1"

    @pytest.mark.asyncio
    async def test_list_grants_filter_by_org_id(self, client, grant_store):
        g1 = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-1",
        )
        g2 = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
            org_id="org-2",
        )
        await grant_store.create_grant(g1)
        await grant_store.create_grant(g2)

        response = client.get("/api/v1/grants?org_id=org-1")
        assert response.status_code == 200
        data = response.json()
        assert len(data["grants"]) == 1
        assert data["grants"][0]["org_id"] == "org-1"

    @pytest.mark.asyncio
    async def test_get_grant_by_id(self, client, grant_store):
        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="test_tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
        )
        await grant_store.create_grant(grant)

        response = client.get(f"/api/v1/grants/{grant.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == grant.id
        assert data["agent_id"] == "agent-1"

    def test_get_grant_not_found(self, client):
        response = client.get("/api/v1/grants/nonexistent")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_revoke_grant(self, client, grant_store):
        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="test_tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
        )
        await grant_store.create_grant(grant)

        response = client.delete(f"/api/v1/grants/{grant.id}")
        assert response.status_code == 200
        assert response.json()["status"] == "revoked"

        # Verify grant is gone
        response = client.get(f"/api/v1/grants/{grant.id}")
        assert response.status_code == 404

    def test_revoke_grant_not_found(self, client):
        response = client.delete("/api/v1/grants/nonexistent")
        assert response.status_code == 404


class TestApprovalsEndpoint:
    def test_list_approvals_empty(self, client):
        response = client.get("/api/v1/approvals")
        assert response.status_code == 200
        data = response.json()
        assert data["approvals"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_list_approvals_with_data(self, client, approval_store):
        from tollgate import AgentContext, Intent, ToolRequest

        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="user")
        intent = Intent(action="test", reason="testing")
        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.WRITE,
            params={},
        )

        await approval_store.create_request(
            ctx, intent, req, "hash123", "needs approval", time.time() + 3600
        )

        response = client.get("/api/v1/approvals")
        assert response.status_code == 200
        data = response.json()
        assert len(data["approvals"]) == 1
        assert data["approvals"][0]["agent_id"] == "agent-1"


class TestMetricsEndpoint:
    def test_metrics_returns_200(self, client):
        response = client.get("/api/v1/metrics")
        assert response.status_code == 200

    def test_metrics_empty_stores(self, client):
        response = client.get("/api/v1/metrics")
        data = response.json()
        assert data["active_grants"] == 0
        assert data["pending_approvals"] == 0

    @pytest.mark.asyncio
    async def test_metrics_with_grants(self, client, grant_store):
        grant = Grant(
            agent_id="agent-1",
            effect=Effect.READ,
            tool="tool",
            action="run",
            resource_type="data",
            expires_at=time.time() + 3600,
            granted_by="admin",
            created_at=time.time(),
        )
        await grant_store.create_grant(grant)

        response = client.get("/api/v1/metrics")
        data = response.json()
        assert data["active_grants"] == 1

    @pytest.mark.asyncio
    async def test_metrics_with_pending_approvals(self, client, approval_store):
        from tollgate import AgentContext, Intent, ToolRequest

        ctx = AgentContext(agent_id="agent-1", version="1.0", owner="user")
        intent = Intent(action="test", reason="testing")
        req = ToolRequest(
            tool="tool",
            action="run",
            resource_type="data",
            effect=Effect.WRITE,
            params={},
        )

        await approval_store.create_request(
            ctx, intent, req, "hash123", "needs approval", time.time() + 3600
        )

        response = client.get("/api/v1/metrics")
        data = response.json()
        assert data["pending_approvals"] == 1


class TestAuditEndpoint:
    def test_audit_not_configured(self, client):
        response = client.get("/api/v1/audit")
        assert response.status_code == 503
        assert "not configured" in response.json()["detail"]


class TestNoStoreConfigured:
    def test_grants_not_configured(self):
        app = create_app()  # No stores
        client = TestClient(app)
        response = client.get("/api/v1/grants")
        assert response.status_code == 503

    def test_approvals_not_configured(self):
        app = create_app()  # No stores
        client = TestClient(app)
        response = client.get("/api/v1/approvals")
        assert response.status_code == 503
