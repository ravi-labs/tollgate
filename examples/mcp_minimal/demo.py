import asyncio
import sys
from pathlib import Path

# Add src to sys.path
root = Path(__file__).parent.parent.parent
sys.path.append(str(root / "src"))

from tollgate import (  # noqa: E402
    AgentContext,
    AutoApprover,
    ControlTower,
    Intent,
    JsonlAuditSink,
    TollgateError,
    ToolRegistry,
    YamlPolicyEvaluator,
)
from tollgate.integrations.mcp import TollgateMCPClient  # noqa: E402


class FakeMCPClient:
    async def call_tool(self, tool_name: str, arguments: dict):
        return f"Result of {tool_name} with {arguments}"


async def main():
    manifest_path = Path(__file__).parent / "manifest.yaml"
    # Create a temporary policy
    policy_path = Path(__file__).parent / "policy.yaml"
    policy_path.write_text("""
rules:
  - id: allow_read
    effect: read
    decision: ALLOW
  - id: ask_write
    effect: write
    decision: ASK
""")

    registry = ToolRegistry(manifest_path)
    tower = ControlTower(
        policy=YamlPolicyEvaluator(policy_path),
        approver=AutoApprover(),
        audit=JsonlAuditSink(Path(__file__).parent / "audit.jsonl"),
    )

    client = TollgateMCPClient(FakeMCPClient(), "file_server", tower, registry)

    ctx = AgentContext(agent_id="test-bot", version="1.0.0", owner="ops")
    intent = Intent(action="demo", reason="testing mcp integration")

    print("\n--- Testing READ tool (ALLOW) ---")
    try:
        res = await client.call_tool("read_file", {"path": "test.txt"}, ctx, intent)
        print(f"Success: {res}")
    except TollgateError as e:
        print(f"Blocked: {e}")

    print("\n--- Testing WRITE tool (ASK -> DENIED by AutoApprover for WRITE) ---")
    try:
        res = await client.call_tool(
            "write_file", {"path": "test.txt", "content": "hi"}, ctx, intent
        )
        print(f"Success: {res}")
    except TollgateError as e:
        print(f"Blocked: {e}")

    print("\n--- Testing UNKNOWN tool (DENY by default) ---")
    try:
        res = await client.call_tool("delete_file", {"path": "test.txt"}, ctx, intent)
        print(f"Success: {res}")
    except TollgateError as e:
        print(f"Blocked: {e}")


if __name__ == "__main__":
    asyncio.run(main())
