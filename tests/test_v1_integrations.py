import pytest

from tollgate import (
    AgentContext,
    AutoApprover,
    ControlTower,
    Intent,
    TollgateApprovalDenied,
    TollgateDenied,
    ToolRegistry,
    YamlPolicyEvaluator,
)
from tollgate.integrations.mcp import TollgateMCPClient
from tollgate.integrations.strands import guard_tools


class MockAudit:
    def emit(self, event):
        pass


@pytest.fixture
def registry(tmp_path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("""
version: "1.0.0"
tools:
  "mcp:server.read": { effect: "read", resource_type: "data" }
  "mcp:server.write": { effect: "write", resource_type: "data" }
  "strands:tool_a": { effect: "read", resource_type: "data" }
""")
    return ToolRegistry(manifest)


@pytest.fixture
def tower(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("""
rules:
  - id: allow_read
    effect: read
    decision: ALLOW
  - id: ask_write
    effect: write
    decision: ASK
""")
    return ControlTower(
        policy=YamlPolicyEvaluator(policy),
        approver=AutoApprover(),
        audit=MockAudit(),
    )


@pytest.mark.asyncio
async def test_mcp_integration(tower, registry):
    class FakeMCP:
        async def call_tool(self, name, _args):
            return f"done {name}"

    client = TollgateMCPClient(FakeMCP(), "server", tower, registry)
    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")

    # 1. ALLOW
    res = await client.call_tool("read", {"x": 1}, ctx, intent)
    assert res == "done read"

    # 2. ASK -> DENY (AutoApprover denies WRITE)
    with pytest.raises(TollgateApprovalDenied):
        await client.call_tool("write", {"x": 1}, ctx, intent)

    # 3. UNKNOWN -> DENY
    with pytest.raises(TollgateDenied):
        await client.call_tool("unknown", {}, ctx, intent)


@pytest.mark.asyncio
async def test_strands_integration(tower, registry):
    async def tool_a(x):
        return f"a:{x}"

    guarded = guard_tools([tool_a], tower, registry)
    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")

    # 1. ALLOW
    res = await guarded[0](5, agent_ctx=ctx, intent=intent)
    assert res == "a:5"

    # 2. UNKNOWN -> DENY (not in registry)
    async def tool_b():
        pass

    guarded_b = guard_tools([tool_b], tower, registry)
    with pytest.raises(TollgateDenied):
        await guarded_b[0]({}, agent_ctx=ctx, intent=intent)
