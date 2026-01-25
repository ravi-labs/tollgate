# tollgate 🚪

Runtime enforcement layer for AI agent tool calls using **Identity + Intent + Policy**.

`tollgate` provides a deterministic safety boundary for AI agents. It ensures every tool call is validated against a policy before execution, with support for human-in-the-loop approvals and structured audit logging.

## ✨ Features

- **Tiny Stable API**: Everything flows through `ControlTower.execute`.
- **Deterministic**: Policy decisions are made by code/config, not LLMs.
- **Framework Agnostic**: Works with LangChain, CrewAI, or custom agent loops.
- **Pluggable**: Custom evaluators, approvers (Slack/Email), and audit sinks (Datadog/SQL).
- **Audit-First**: Correlation IDs link every intent to a tool execution and outcome.

## 🚀 60-Second Quickstart

### 1. Define Policy (`policy.yaml`)
```yaml
rules:
  - id: allow_read
    tool: database
    action: query
    decision: ALLOW
  - id: ask_delete
    tool: database
    action: delete_row
    decision: ASK
    reason: "Deletions require human oversight."
```

### 2. Integrate
```python
from tollgate import ControlTower, YamlPolicyEvaluator, CliApprover, JsonlAuditSink, ToolRequest, Effect

# Setup the tower
tower = ControlTower(
    policy=YamlPolicyEvaluator("policy.yaml"),
    approver=CliApprover(),
    audit=JsonlAuditSink("audit.jsonl")
)

# Guard your tool calls
def delete_user(user_id):
    print(f"User {user_id} deleted.")

# Inside your agent loop
tower.execute(
    agent_ctx=my_agent_context,
    intent=my_intent,
    tool_request=ToolRequest(
        tool="database", action="delete_row", 
        resource_type="user", effect=Effect.DELETE, 
        params={"user_id": 123}
    ),
    tool_callable=delete_user
)
```

## 🛠 Installation

```bash
pip install tollgate
```

## 📂 Example: Mock Tickets
A full demo is available in `examples/mock_tickets/`. It simulates an agent attempting to close stale tickets.

```bash
# Setup
pip install -e ".[dev]"

# Run Demo
python examples/mock_tickets/demo.py
```

## 📜 Development

```bash
make install
make test
make lint
```

## ⚖️ License
Apache-2.0
