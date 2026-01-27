# Tollgate: Integration Effort Comparison 📊

This guide demonstrates the minimal changes required to integrate `tollgate` into your existing AI agent workflows.

> [!CAUTION]
> **Disclaimer**: This project is an exploratory implementation intended for learning and discussion. It is not production-hardened and comes with no guarantees.

---

## 🔹 Scenario 1: Plain Python Tools
**Effort:** ~5 lines of setup + 1 wrapper call.

### ❌ Before Tollgate
Directly calling a tool function with no gating.

```python
def delete_database(db_id: str):
    print(f"Deleting database {db_id}...")

# No protection - if the agent decides to call this, it happens.
delete_database("prod-db-01")
```

### ✅ After Tollgate
Wrapping the tool to ensure it passes through the Control Tower.

```python
from tollgate import ControlTower, ToolRegistry, YamlPolicyEvaluator, CliApprover, JsonlAuditSink
from tollgate.helpers import wrap_tool

# 1. Setup (One-time)
registry = ToolRegistry("manifest.yaml")
tower = ControlTower(
    policy=YamlPolicyEvaluator("policy.yaml"),
    approver=CliApprover(),
    audit=JsonlAuditSink("audit.jsonl")
)

# 2. Wrap tool (Minimal change)
guarded_delete = wrap_tool(tower, delete_database, 
                           tool="db_admin", action="delete", 
                           resource_type="database", effect="delete")

# 3. Secure execution
guarded_delete(agent_ctx, intent, db_id="prod-db-01")
```

---

## 🔹 Scenario 2: LangChain Integration
**Effort:** ~5 lines of setup + 1 line for `guard_tools`.

### ❌ Before Tollgate
Ungated tools passed directly to an agent.

```python
from langchain.agents import initialize_agent

tools = [SearchTool(), CalculatorTool()]
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")

# Agent calls tools freely
agent.run("Calculate the GDP of France.")
```

### ✅ After Tollgate
Interception at the tool boundary.

```python
from tollgate.interceptors.langchain import guard_tools

# 1. Setup Tollgate (as shown in Scenario 1)
# ... tower/registry setup ...

# 2. Guard tools (1 line change)
guarded_tools = guard_tools(tools, tower, registry)

# 3. Secure execution
agent = initialize_agent(guarded_tools, llm, ...)
# Tools now require agent_ctx and intent to proceed (or they default to DENY)
```

---

## 🔹 Scenario 3: MCP (Model Context Protocol)
**Effort:** Swapping the client class.

### ❌ Before Tollgate
Direct usage of an MCP client.

```python
from mcp_client import Client

client = Client(server_url="...")
# Ungated call
await client.call_tool("read_file", {"path": "secrets.txt"})
```

### ✅ After Tollgate
Using the `TollgateMCPClient` wrapper.

```python
from tollgate.integrations.mcp import TollgateMCPClient

# 1. Setup Tollgate (as shown in Scenario 1)
# ... tower/registry setup ...

# 2. Swap Client (1 line change)
gated_client = TollgateMCPClient(base_client, server_name="fs", tower=tower, registry=registry)

# 3. Secure execution
await gated_client.call_tool("read_file", {"path": "secrets.txt"}, ctx, intent)
```

---

## 📈 Integration Effort Summary

| Feature | Effort | Lines of Code Added |
| :--- | :--- | :--- |
| **Initial Setup** | Minimal | ~5-8 lines |
| **Tool Wrapping** | Near-Zero | 1 line per toolset |
| **In-Loop Change**| Zero | None (Enforcement is at the boundary) |

### Why use Tollgate?
1. **Separation of Concerns**: Your agent logic stays clean; security is handled at the boundary.
2. **Deterministic Safety**: No more "hallucinated" tool calls causing real-world damage.
3. **Audit Readiness**: Instant, structured logs for compliance and debugging.
