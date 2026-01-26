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
from tollgate.integrations.strands import guard_tools  # noqa: E402


async def get_weather(location: str):
    return f"Sunny in {location}"


class Thermostat:
    name = "set_temp"
    description = "Set the temperature"

    def run(self, temp: int):
        return f"Temperature set to {temp}"


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

    # Wrap tools
    raw_tools = [get_weather, Thermostat()]
    guarded = guard_tools(raw_tools, tower, registry)

    ctx = AgentContext(agent_id="test-bot", version="1.0.0", owner="ops")
    intent = Intent(action="demo", reason="testing strands integration")

    print("\n--- Testing Strands READ tool (ALLOW) ---")
    try:
        weather_tool = next(t for t in guarded if t.name == "get_weather")
        res = await weather_tool("London", agent_ctx=ctx, intent=intent)
        print(f"Success: {res}")
    except TollgateError as e:
        print(f"Blocked: {e}")

    print("\n--- Testing Strands WRITE tool (ASK -> DENIED by AutoApprover) ---")
    try:
        temp_tool = next(t for t in guarded if t.name == "set_temp")
        res = await temp_tool({"temp": 22}, agent_ctx=ctx, intent=intent)
        print(f"Success: {res}")
    except TollgateError as e:
        print(f"Blocked: {e}")


if __name__ == "__main__":
    asyncio.run(main())
