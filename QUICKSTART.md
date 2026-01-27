# tollgate Quickstart Guide 🚀

Get started with `tollgate` in minutes. This guide covers the basic setup and integration options for various AI frameworks.

> [!CAUTION]
> **Disclaimer**: This project is an exploratory implementation intended for learning and discussion. It is not production-hardened and comes with no guarantees.

---

## 0. Key Concepts

Tollgate requires three pieces of context for every decision:
- **AgentContext**: Who is asking? (agent_id, version, owner)
- **Intent**: What is the goal? (action, reason)
- **Registry**: What does this tool actually do? (defined in `manifest.yaml`)

---

## 1. Installation

```bash
pip install tollgate
```

---

## 2. Shared Setup (Registry & Policy)

Every integration requires a **Tool Registry** (to define tool effects) and a **Policy** (to define rules).

### Define `manifest.yaml`
```yaml
version: "1.0.0"
tools:
  "mcp:file_server.read_file": { effect: "read", resource_type: "file" }
  "strands:get_weather": { effect: "read", resource_type: "weather" }
  "langchain:delete_user": { effect: "delete", resource_type: "user" }
  "openai:process_payment": { effect: "write", resource_type: "payment" }
```

### Define `policy.yaml`
```yaml
rules:
  - id: allow_reads
    effect: read
    decision: ALLOW
  - id: ask_deletions
    effect: delete
    decision: ASK
    reason: "Sensitive deletion requires human confirmation."
```

---

## 3. Integration Options

Choose the integration that fits your agent framework.

### 🔹 Option A: MCP (Model Context Protocol)
Wrap your MCP client to gate all tool calls automatically.

```python
from tollgate import ControlTower, ToolRegistry, YamlPolicyEvaluator, CliApprover, JsonlAuditSink
from tollgate.integrations.mcp import TollgateMCPClient

# Initialize Tollgate
registry = ToolRegistry("manifest.yaml")
tower = ControlTower(
    policy=YamlPolicyEvaluator("policy.yaml"),
    approver=CliApprover(),
    audit=JsonlAuditSink("audit.jsonl")
)

# Wrap your MCP client
gated_client = TollgateMCPClient(base_client, server_name="file_server", tower=tower, registry=registry)

# Use it like a normal client
await gated_client.call_tool("read_file", {"path": "data.txt"}, agent_ctx=ctx, intent=intent)
```

### 🔹 Option B: Strands Agents
Guard your Strands tools (functions or objects).

```python
from tollgate.integrations.strands import guard_tools

# Wrap your tools
guarded_tools = guard_tools([get_weather], tower, registry)

# Call the guarded tool
await guarded_tools[0]("London", agent_ctx=ctx, intent=intent)
```

### 🔹 Option C: LangChain
Use `guard_tools` to wrap LangChain tool objects.

```python
from tollgate.interceptors.langchain import guard_tools

# Wrap LangChain tools
guarded_lc_tools = guard_tools(my_tools, tower, registry)

# Tools now require agent_ctx and intent
await guarded_lc_tools[0].ainvoke({"input": "query"}, agent_ctx=ctx, intent=intent)
```

### 🔹 Option D: OpenAI Tools
Run OpenAI-formatted tool calls through Tollgate.

```python
from tollgate.interceptors.openai import OpenAIToolRunner

runner = OpenAIToolRunner(tower, registry)
tool_map = {"process_payment": my_payment_func}

# Pass the tool calls list from OpenAI response
results = await runner.run_async(openai_response.tool_calls, tool_map, agent_ctx=ctx, intent=intent)
```

---

## 4. Run the Full Demo

Explore the built-in mock tickets demo to see ALLOW, DENY, and ASK scenarios in action.

```bash
# From the project root
python examples/mock_tickets/demo.py
```

## 🛡️ Safe Defaults
Remember: Any tool **not** in the registry or any action **not** matched by a policy will be **DENIED** by default in v1.0.0.

---

**[📊 See the Before vs. After Integration Comparison](./COMPARISON.md)**
