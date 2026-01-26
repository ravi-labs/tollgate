# Mock Tickets Demo (v1)

This example demonstrates the `tollgate` v1 architecture protecting a ticket management system using **Registry-based gating** and **Interception**.

## v1 Core Features Demonstrated
1. **Registry Gating**: The agent can only call tools defined in `manifest.yaml`.
2. **Interception**: The agent uses a `LangChainAdapter` to gate tool calls automatically.
3. **Trust Model**: VIP status is checked using trusted metadata provided during the tool call.
4. **Async Approvals**: Human-in-the-loop approvals for stale ticket closures.

## Scenarios
1. **ALLOW**: Listing stale tickets (Read access to `ticket_list` is pre-approved).
2. **DENY**: Closing a VIP ticket (Strictly forbidden by policy).
3. **ASK**: Closing a stale ticket (Requires human approval via CLI).

## How to Run
```bash
# From the project root
python examples/mock_tickets/demo.py
```

## Audit Logs
All decisions, approval requests, and execution outcomes are recorded in `audit.jsonl` with full integrity hashes.

