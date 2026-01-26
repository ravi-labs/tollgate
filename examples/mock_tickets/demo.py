import asyncio
import sys
from pathlib import Path

# Add project root and src to sys.path
root = Path(__file__).parent.parent.parent
sys.path.append(str(root))
sys.path.append(str(root / "src"))

from examples.mock_tickets.agent import TicketCleanupAgent  # noqa: E402
from tollgate import (  # noqa: E402
    CliApprover,
    ControlTower,
    JsonlAuditSink,
    ToolRegistry,
    YamlPolicyEvaluator,
)


async def main():
    policy_path = root / "policies" / "default.yaml"
    manifest_path = Path(__file__).parent / "manifest.yaml"
    audit_path = Path(__file__).parent / "audit.jsonl"

    # 1. Setup Tollgate
    registry = ToolRegistry(manifest_path)
    tower = ControlTower(
        policy=YamlPolicyEvaluator(policy_path),
        approver=CliApprover(),
        audit=JsonlAuditSink(audit_path),
    )

    # 2. Run Agent
    agent = TicketCleanupAgent(tower, registry)

    print("Starting Mock Tickets v1 Demo (Async)...")
    print(f"Policy: {policy_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Audit Log: {audit_path}")

    try:
        await agent.run()
    except KeyboardInterrupt:
        print("\nDemo stopped.")


if __name__ == "__main__":
    asyncio.run(main())
