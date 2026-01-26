import pytest

from tollgate import (
    AgentContext,
    ApprovalOutcome,
    ControlTower,
    DecisionType,
    Intent,
    ToolRegistry,
)
from tollgate.interceptors.langchain import guard_tools
from tollgate.interceptors.openai import OpenAIToolRunner


class MockPolicy:
    def evaluate(self, _ctx, _intent, _req):
        from tollgate import Decision

        return Decision(decision=DecisionType.ALLOW, reason="ok", policy_version="1")


class MockApprover:
    async def request_approval_async(self, *_args):
        return ApprovalOutcome.APPROVED


class MockAudit:
    def emit(self, event):
        pass


@pytest.fixture
def tower():
    return ControlTower(MockPolicy(), MockApprover(), MockAudit())


@pytest.fixture
def registry(tmp_path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("""
tools:
  "langchain:test_tool": { effect: "write", resource_type: "data" }
  "openai:test_func": { effect: "delete", resource_type: "user" }
""")
    return ToolRegistry(manifest)


@pytest.mark.asyncio
async def test_langchain_interception(tower, registry):
    class FakeTool:
        name = "test_tool"
        description = "desc"

        async def ainvoke(self, tool_input, **_kwargs):
            return f"done {tool_input['x']}"

    guarded = guard_tools([FakeTool()], tower, registry)[0]
    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")

    # This should go through the tower, resolve effect='write' from registry
    res = await guarded.ainvoke({"x": 1}, agent_ctx=ctx, intent=intent)
    assert res == "done 1"


@pytest.mark.asyncio
async def test_openai_interception(tower, registry):
    runner = OpenAIToolRunner(tower, registry)
    tool_map = {"test_func": lambda item_id: f"deleted {item_id}"}

    ctx = AgentContext("a", "1", "o")
    intent = Intent("i", "r")

    # Mock OpenAI tool call format
    tool_calls = [
        {
            "function": {
                "name": "test_func",
                "arguments": '{"item_id": "user_123"}',
            }
        }
    ]

    results = await runner.run_async(tool_calls, tool_map, ctx, intent)
    assert results == ["deleted user_123"]
