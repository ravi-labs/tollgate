# tollgate Quickstart Guide

Get started with `tollgate` in minutes. This guide covers basic setup, security hardening, and integration options for various AI frameworks.

> [!CAUTION]
> **Disclaimer**: This project is an exploratory implementation intended for learning and discussion. It is not production-hardened and comes with no guarantees.

---

## Table of Contents

1. [Key Concepts](#key-concepts)
2. [Installation](#installation)
3. [Basic Setup](#basic-setup)
4. [Security Hardening](#security-hardening)
5. [Framework Integrations](#framework-integrations)
6. [Testing Your Policies](#testing-your-policies)
7. [Next Steps](#next-steps)

---

## Key Concepts

Tollgate requires three pieces of context for every decision:

| Concept | Description |
|---------|-------------|
| **AgentContext** | Who is asking? (`agent_id`, `version`, `owner`, `delegated_by`) |
| **Intent** | What is the goal? (`action`, `reason`, `confidence`) |
| **ToolRequest** | What tool and parameters? (`tool`, `action`, `effect`, `params`) |

---

## Installation

```bash
# Basic installation
pip install tollgate

# With Redis support (for distributed deployments)
pip install tollgate[redis]
```

---

## Basic Setup

### Step 1: Define Your Tool Manifest

The manifest declares what each tool does (its effect on the world).

```yaml
# manifest.yaml
version: "1.0.0"
tools:
  "api:weather":
    effect: read
    resource_type: weather
  "api:file_write":
    effect: write
    resource_type: file
    params_schema:
      type: object
      required: [path, content]
      properties:
        path: { type: string, maxLength: 255 }
        content: { type: string }
  "api:send_email":
    effect: notify
    resource_type: email
```

### Step 2: Define Your Policy

Policies determine what actions are allowed, denied, or require approval.

```yaml
# policy.yaml
version: "1.0"
rules:
  # Allow all read operations
  - id: allow_reads
    effect: read
    decision: ALLOW
    reason: "Read operations are safe"

  # Require approval for writes
  - id: ask_writes
    effect: write
    decision: ASK
    reason: "Write operations require approval"

  # Default deny everything else
  - id: deny_default
    decision: DENY
    reason: "No matching rule"
```

### Step 3: Create the ControlTower

```python
import asyncio
from tollgate import (
    ControlTower, YamlPolicyEvaluator, ToolRegistry,
    AutoApprover, JsonlAuditSink, AgentContext, Intent,
    ToolRequest, Effect
)

async def main():
    # Initialize components
    registry = ToolRegistry("manifest.yaml")
    policy = YamlPolicyEvaluator("policy.yaml")
    audit = JsonlAuditSink("audit.jsonl")

    # Create the enforcement tower
    tower = ControlTower(
        policy=policy,
        approver=AutoApprover(),  # For testing; use CliApprover in production
        audit=audit,
        registry=registry,
    )

    # Define who is making the request
    agent = AgentContext(
        agent_id="my-agent",
        version="1.0.0",
        owner="my-team",
    )

    # Define the intent
    intent = Intent(
        action="fetch_weather",
        reason="User asked about London weather",
    )

    # Define the tool request
    request = ToolRequest(
        tool="api:weather",
        action="get",
        resource_type="weather",
        effect=Effect.READ,
        params={"city": "London"},
        manifest_version="1.0.0",
    )

    # Execute with enforcement
    result = await tower.execute_async(
        agent, intent, request,
        lambda: {"weather": "sunny", "temp": 22},  # Your actual tool function
    )

    print(f"Result: {result}")

asyncio.run(main())
```

---

## Security Hardening

Add these security layers for production use.

### Rate Limiting

Prevent abuse with sliding window rate limits.

```python
from tollgate import InMemoryRateLimiter

limiter = InMemoryRateLimiter([
    # Global: 100 calls/minute
    {"agent_id": "*", "tool": "*", "max_calls": 100, "window_seconds": 60},
    # Writes: 10 calls/minute
    {"agent_id": "*", "effect": "write", "max_calls": 10, "window_seconds": 60},
])

tower = ControlTower(..., rate_limiter=limiter)
```

### Agent Identity Signing

Prevent agent spoofing with HMAC signatures.

```python
from tollgate import sign_agent_context, make_verifier

secret = b"your-secret-key"

# Sign the agent context
signed_agent = sign_agent_context(agent, secret)

# Verify signatures in ControlTower
tower = ControlTower(..., verify_fn=make_verifier(secret))
```

### Circuit Breaker

Auto-disable failing tools.

```python
from tollgate import InMemoryCircuitBreaker

breaker = InMemoryCircuitBreaker(
    failure_threshold=5,    # Open after 5 failures
    cooldown_seconds=60,    # Wait 60s before retry
)

tower = ControlTower(..., circuit_breaker=breaker)
```

### Network Guard

Control which URLs tools can access.

```python
from tollgate import NetworkGuard

guard = NetworkGuard(
    default="deny",
    allowlist=[
        {"pattern": "https://api.github.com/*"},
        {"pattern": "https://api.openai.com/*"},
    ],
    blocklist=[
        {"pattern": "http://*"},  # Block insecure HTTP
    ],
)

tower = ControlTower(..., network_guard=guard)
```

### Manifest Signing

Sign manifests at build time to prevent tampering.

```python
from tollgate import sign_manifest, ToolRegistry

# At build time (in CI)
sign_manifest("manifest.yaml", secret_key=b"build-secret")

# At runtime (rejects tampering)
registry = ToolRegistry("manifest.yaml", signing_key=b"build-secret")
```

### Anomaly Detection

Detect unusual patterns in tool usage.

```python
from tollgate import AnomalyDetector, CompositeAuditSink, JsonlAuditSink

detector = AnomalyDetector(
    z_score_threshold=3.0,
    alert_callback=lambda alert: print(f"ALERT: {alert.message}"),
)

audit = CompositeAuditSink([
    JsonlAuditSink("audit.jsonl"),
    detector,
])

tower = ControlTower(..., audit=audit)
```

---

## Framework Integrations

### MCP (Model Context Protocol)

```python
from tollgate.integrations.mcp import TollgateMCPClient

gated_client = TollgateMCPClient(
    base_client,
    server_name="my_server",
    tower=tower,
    registry=registry,
)

await gated_client.call_tool(
    "read_file",
    {"path": "data.txt"},
    agent_ctx=agent,
    intent=intent,
)
```

### Strands Agents

```python
from tollgate.integrations.strands import guard_tools

guarded_tools = guard_tools(my_tools, tower, registry)

await guarded_tools[0]("input", agent_ctx=agent, intent=intent)
```

### LangChain

```python
from tollgate.interceptors.langchain import guard_tools

guarded_lc_tools = guard_tools(my_langchain_tools, tower, registry)

await guarded_lc_tools[0].ainvoke(
    {"input": "query"},
    agent_ctx=agent,
    intent=intent,
)
```

### OpenAI Tools

```python
from tollgate.interceptors.openai import OpenAIToolRunner

runner = OpenAIToolRunner(tower, registry)
tool_map = {"process_data": my_process_func}

results = await runner.run_async(
    openai_response.tool_calls,
    tool_map,
    agent_ctx=agent,
    intent=intent,
)
```

---

## Testing Your Policies

### Create Test Scenarios

```yaml
# test_scenarios.yaml
scenarios:
  - name: "Allow read operations"
    agent:
      agent_id: "test-agent"
      version: "1.0"
      owner: "test"
    intent:
      action: "fetch_data"
      reason: "Testing"
    tool_request:
      tool: "api:weather"
      action: "get"
      resource_type: "weather"
      effect: "read"
      manifest_version: "1.0.0"
    expected:
      decision: "ALLOW"
      policy_id: "allow_reads"

  - name: "Ask for write operations"
    tool_request:
      tool: "api:file_write"
      effect: "write"
    expected:
      decision: "ASK"

  - name: "Deny unknown effects"
    tool_request:
      tool: "unknown:tool"
      effect: "unknown"
    expected:
      decision: "DENY"
```

### Run Tests

```bash
# CLI
tollgate test-policy policy.yaml --scenarios test_scenarios.yaml

# Python
from tollgate import PolicyTestRunner

runner = PolicyTestRunner("policy.yaml", "test_scenarios.yaml")
results = runner.run()

print(results.summary())
assert results.all_passed  # For CI
```

---

## Multi-Agent Delegation

Track and control agent delegation chains.

```python
from tollgate import AgentContext

# Sub-agent with delegation chain
sub_agent = AgentContext(
    agent_id="worker-agent",
    version="1.0",
    owner="team-a",
    delegated_by=("orchestrator", "router"),  # Who delegated to this agent
)

print(sub_agent.delegation_depth)  # 2
print(sub_agent.root_agent)        # "orchestrator"
```

### Delegation Policy Rules

```yaml
# policy.yaml
rules:
  # Block deep delegation chains
  - id: block_deep_chains
    agent:
      max_delegation_depth: 2
    effect: write
    decision: DENY
    reason: "Delegation chain too deep"

  # Only allow trusted delegators
  - id: allow_trusted_delegation
    agent:
      allowed_delegators:
        - "orchestrator"
        - "ci-runner"
    effect: write
    decision: ALLOW
```

---

## Persistent Backends

For production, use persistent storage instead of in-memory stores.

### SQLite (Single Process)

```python
from tollgate.backends import SQLiteGrantStore, SQLiteApprovalStore

grant_store = SQLiteGrantStore("tollgate.db")
approval_store = SQLiteApprovalStore("tollgate.db")

tower = ControlTower(
    ...,
    grant_store=grant_store,
    approval_store=approval_store,
)
```

### Redis (Distributed)

```python
from tollgate.backends import RedisGrantStore, RedisApprovalStore

grant_store = RedisGrantStore(redis_url="redis://localhost:6379/0")
approval_store = RedisApprovalStore(redis_url="redis://localhost:6379/0")
```

---

## Next Steps

- **[FEATURES.md](./FEATURES.md)** - Complete feature guide with all options
- **[SECURITY.md](./SECURITY.md)** - Security best practices and checklist
- **[COMPARISON.md](./COMPARISON.md)** - Framework integration comparison
- **[examples/](./examples/)** - Working examples for each integration

### Safe Defaults

Remember: Any tool **not** in the registry or any action **not** matched by a policy will be **DENIED** by default. This is intentional — fail closed, not open.
