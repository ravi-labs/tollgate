# tollgate

Runtime enforcement layer for AI agent tool calls using **Identity + Intent + Policy**.

`tollgate` provides a deterministic safety boundary for AI agents. It ensures every tool call is validated against a policy before execution, with support for async human-in-the-loop approvals, framework interception (MCP, Strands, LangChain, OpenAI), and structured audit logging.

> [!CAUTION]
> **Disclaimer**: This project is an exploratory implementation intended for learning and discussion. It is not production-hardened and comes with no guarantees.

**[Quickstart Guide](./QUICKSTART.md) | [Feature Guide](./FEATURES.md) | [Integration Comparison](./COMPARISON.md) | [Security](./SECURITY.md)**

```
                          +-----------------+
                          |    AI Agent     |
                          +--------+--------+
                                   |
                    +--------------v---------------+
                    |     Tollgate ControlTower    |
                    |------------------------------|
                    | 1. Identity Verification     |
                    | 2. Circuit Breaker Check     |
                    | 3. Rate Limiting             |
                    | 4. Policy Evaluation         |
                    | 5. Network Guard             |
                    | 6. Parameter Validation      |
                    | 7. Constraint Checking       |
                    +--------------+---------------+
                                   |
              +--------------------+--------------------+
              |                    |                    |
              v                    v                    v
         +--------+           +--------+          +--------+
         | ALLOW  |           |  ASK   |          |  DENY  |
         +---+----+           +---+----+          +---+----+
             |                    |                    |
             v                    v                    v
        +--------+        +-------------+        +--------+
        |Execute |        |Human/Grant  |        | Block  |
        | Tool   |        | Approval    |        | & Log  |
        +---+----+        +------+------+        +---+----+
             \                   |                   /
              \                  |                  /
               +--------+--------+--------+--------+
                        |
                        v
                  +-----------+
                  | Audit Log | --> Anomaly Detection
                  +-----------+
```

## Installation

```bash
pip install tollgate

# Optional: For Redis-backed persistent stores
pip install tollgate[redis]
```

## Core Concepts

| Concept | Description |
|---------|-------------|
| **AgentContext** | Who is asking? (`agent_id`, `version`, `owner`, `delegated_by`) |
| **Intent** | What is the goal? (`action`, `reason`, `confidence`) |
| **ToolRequest** | What tool and parameters? (`tool`, `action`, `effect`, `params`) |
| **Decision** | Policy result: `ALLOW`, `ASK`, or `DENY` |
| **Grant** | Pre-authorization that bypasses ASK for specific patterns |

## Core Principles

1. **Interception-First**: Enforcement at the tool execution boundary via adapters
2. **Safe Defaults**: Unknown effects or resources default to **DENY**
3. **Trust Model**: Tool metadata trusted only from developer-controlled **Tool Registry**
4. **Approval Integrity**: Approvals bound to request hash with replay protection
5. **Async-First**: Native async support with non-blocking approvals
6. **Audit Integrity**: Every decision recorded with cryptographic context
7. **Defense in Depth**: Multiple security layers (rate limiting, circuit breaker, network guard)

## Quick Example

```python
import asyncio
from tollgate import (
    ControlTower, YamlPolicyEvaluator, ToolRegistry,
    AutoApprover, JsonlAuditSink, AgentContext, Intent,
    ToolRequest, Effect
)

async def main():
    # Setup
    policy = YamlPolicyEvaluator("policy.yaml")
    registry = ToolRegistry("manifest.yaml")
    audit = JsonlAuditSink("audit.jsonl")

    tower = ControlTower(policy, AutoApprover(), audit, registry=registry)

    # Define context
    agent = AgentContext(agent_id="my-agent", version="1.0", owner="my-team")
    intent = Intent(action="fetch_data", reason="User requested weather info")
    request = ToolRequest(
        tool="api:weather",
        action="get",
        resource_type="weather",
        effect=Effect.READ,
        params={"city": "London"},
        manifest_version="1.0.0"
    )

    # Execute with enforcement
    result = await tower.execute_async(
        agent, intent, request,
        lambda: fetch_weather("London")  # Your tool function
    )
    print(result)

asyncio.run(main())
```

## Feature Highlights

### Security Hardening

| Feature | Description |
|---------|-------------|
| **Parameter Validation** | JSON Schema validation for tool parameters |
| **Rate Limiting** | Per-agent, per-tool, per-effect rate limits |
| **Agent Identity Signing** | HMAC-SHA256 verification of agent contexts |
| **URL Constraints** | Per-tool URL allowlisting/blocklisting |
| **Webhook Alerts** | Real-time alerts for blocked/denied events |
| **Audit Schema Versioning** | Forward-compatible audit event schemas |

```python
from tollgate import InMemoryRateLimiter, sign_agent_context, make_verifier

# Rate limiting
limiter = InMemoryRateLimiter([
    {"agent_id": "*", "tool": "api:*", "max_calls": 100, "window_seconds": 60},
    {"agent_id": "*", "effect": "write", "max_calls": 10, "window_seconds": 60},
])

# Agent identity signing
secret = b"your-secret-key"
signed_agent = sign_agent_context(agent, secret)
tower = ControlTower(..., verify_fn=make_verifier(secret), rate_limiter=limiter)
```

### Resilience & Protection

| Feature | Description |
|---------|-------------|
| **Circuit Breaker** | Auto-disable failing tools after threshold |
| **Manifest Signing** | HMAC-SHA256 integrity verification for manifests |
| **NetworkGuard** | Global URL policy enforcement |
| **Persistent Backends** | SQLite and Redis stores for grants/approvals |

```python
from tollgate import InMemoryCircuitBreaker, NetworkGuard, sign_manifest
from tollgate.backends import SQLiteGrantStore

# Circuit breaker - opens after 5 failures, 60s cooldown
breaker = InMemoryCircuitBreaker(failure_threshold=5, cooldown_seconds=60)

# Global network policy
guard = NetworkGuard(
    default="deny",
    allowlist=[
        {"pattern": "https://api.github.com/*"},
        {"pattern": "https://api.openai.com/*"},
    ],
    blocklist=[
        {"pattern": "http://*"},  # Block insecure
    ]
)

# Sign your manifest at build time
sign_manifest("manifest.yaml", secret_key=b"build-secret")

# Load with signature verification
registry = ToolRegistry("manifest.yaml", signing_key=b"build-secret")

tower = ControlTower(..., circuit_breaker=breaker, network_guard=guard)
```

### Defense in Depth

| Feature | Description |
|---------|-------------|
| **Multi-Agent Delegation** | Track and control delegation chains |
| **Policy Testing Framework** | CI-friendly declarative policy testing |
| **Context Integrity Monitor** | Detect memory/context poisoning |
| **Anomaly Detection** | Z-score based rate spike detection |

```python
from tollgate import (
    AgentContext, PolicyTestRunner,
    ContextIntegrityMonitor, AnomalyDetector
)

# Delegation chain tracking
sub_agent = AgentContext(
    agent_id="sub-agent",
    version="1.0",
    owner="team-a",
    delegated_by=("orchestrator", "router"),  # Delegation chain
)
print(sub_agent.delegation_depth)  # 2
print(sub_agent.root_agent)        # "orchestrator"

# Policy testing (CI integration)
runner = PolicyTestRunner("policy.yaml", "test_scenarios.yaml")
results = runner.run()
assert results.all_passed  # Fail CI if policy regressed

# Context integrity monitoring
monitor = ContextIntegrityMonitor()
monitor.snapshot("agent-1", "turn-1", {"system_prompt": "You are helpful..."})
# Later...
result = monitor.verify("agent-1", "turn-1", current_context)
if not result.is_valid:
    print(f"Context tampered! Changed: {result.changed_fields}")

# Anomaly detection (plugs into audit pipeline)
detector = AnomalyDetector(z_score_threshold=3.0)
composite_sink = CompositeAuditSink([jsonl_sink, detector])
```

### CLI Tools

```bash
# Test policies against scenarios (for CI)
tollgate test-policy policy.yaml --scenarios test_scenarios.yaml
```

## Framework Integrations

### Session Grants
Pre-authorize specific actions to bypass human approval:

```python
from tollgate import Grant, InMemoryGrantStore, Effect

grant_store = InMemoryGrantStore()
tower = ControlTower(..., grant_store=grant_store)

# Issue a grant (after initial approval)
grant = Grant(
    agent_id="my-agent",
    effect=Effect.WRITE,
    tool="mcp:*",  # Wildcard: any MCP tool
    action=None,   # Wildcard: any action
    resource_type=None,
    expires_at=time.time() + 3600,
    granted_by="admin",
    created_at=time.time()
)
await grant_store.create_grant(grant)
```

### MCP (Model Context Protocol)
```python
from tollgate.integrations.mcp import TollgateMCPClient

registry = ToolRegistry("manifest.yaml")
tower = ControlTower(...)
client = TollgateMCPClient(base_client, "my_server", tower=tower, registry=registry)

await client.call_tool("read_data", {"id": 1}, agent_ctx=ctx, intent=intent)
```

### Strands / LangChain
```python
from tollgate.integrations.strands import guard_tools

guarded = guard_tools(my_tools, tower, registry)
await guarded[0]("input", agent_ctx=ctx, intent=intent)
```

## Policy Example

```yaml
# policy.yaml
version: "1.0"
rules:
  # Allow reads for verified agents
  - id: allow_reads
    effect: read
    decision: ALLOW
    reason: "Read operations are safe"

  # Block deep delegation chains
  - id: block_deep_delegation
    effect: write
    decision: DENY
    reason: "Delegation too deep"
    agent:
      max_delegation_depth: 2

  # Require approval for writes from untrusted delegators
  - id: ask_untrusted_writes
    effect: write
    decision: ASK
    reason: "Write requires human approval"
    agent:
      blocked_delegators:
        - "untrusted-agent"

  # Default deny
  - id: deny_default
    decision: DENY
    reason: "No matching rule"
```

## Persistent Backends

For production deployments, use persistent stores:

```python
# SQLite (zero dependencies, single-process)
from tollgate.backends import SQLiteGrantStore, SQLiteApprovalStore

grant_store = SQLiteGrantStore("tollgate.db")
approval_store = SQLiteApprovalStore("tollgate.db")

# Redis (multi-process, distributed)
from tollgate.backends import RedisGrantStore, RedisApprovalStore

grant_store = RedisGrantStore(redis_url="redis://localhost:6379/0")
approval_store = RedisApprovalStore(redis_url="redis://localhost:6379/0")
```

## Development

```bash
# Install
make install

# Run Tests (188 tests)
make test

# Run Examples
python examples/mcp_minimal/demo.py
python examples/strands_minimal/demo.py
python examples/mock_tickets/demo.py
```

## Documentation

- **[QUICKSTART.md](./QUICKSTART.md)** - Get started in 5 minutes
- **[FEATURES.md](./FEATURES.md)** - Complete feature guide
- **[COMPARISON.md](./COMPARISON.md)** - Integration effort comparison
- **[SECURITY.md](./SECURITY.md)** - Security model and guarantees
- **[CHANGELOG.md](./CHANGELOG.md)** - Version history
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - How to contribute

## License

Apache-2.0
