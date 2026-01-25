# Mock Tickets Demo

This example demonstrates how `tollgate` can be used to protect a ticket management system.

## Scenarios
1. **ALLOW**: Listing tickets older than 90 days.
2. **DENY**: Attempting to close a VIP ticket (T-2, T-10, T-19).
3. **ASK**: Attempting to close a standard ticket older than 90 days.

## How to Run
Ensure you are in the project root and have the library installed (or `src` in your `PYTHONPATH`).

```bash
# Run the demo
python examples/mock_tickets/demo.py
```

## Expected Behavior
- The agent will first list all tickets older than 90 days (ALLOWED).
- For each ticket:
    - If `is_vip` is `true`, `tollgate` will raise `TollgateDenied`.
    - If `age_days` >= 90, `tollgate` will prompt you for approval (CLI).
- All decisions are logged to `audit.jsonl` in this directory.
