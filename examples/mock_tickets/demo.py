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
    YamlPolicyEvaluator,
)


def main():
    policy_path = root / "policies" / "default.yaml"
    audit_path = Path(__file__).parent / "audit.jsonl"

    # 1. Setup Tollgate
    tower = ControlTower(
        policy=YamlPolicyEvaluator(policy_path),
        approver=CliApprover(),
        audit=JsonlAuditSink(audit_path),
    )

    # 2. Run Agent
    agent = TicketCleanupAgent(tower)

    print("Starting Mock Tickets Demo...")
    print(f"Policy: {policy_path}")
    print(f"Audit Log: {audit_path}")

    try:
        agent.run()
    except KeyboardInterrupt:
        print("\nDemo stopped.")


if __name__ == "__main__":
    main()
