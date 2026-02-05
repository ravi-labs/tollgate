# Tollgate Feature Guide

This guide covers all features in Tollgate, organized by security layer.

## Table of Contents

1. [Core Components](#core-components)
2. [Layer 1: Identity & Authentication](#layer-1-identity--authentication)
3. [Layer 2: Rate Limiting & Circuit Breaker](#layer-2-rate-limiting--circuit-breaker)
4. [Layer 3: Policy Evaluation](#layer-3-policy-evaluation)
5. [Layer 4: Network & Parameter Validation](#layer-4-network--parameter-validation)
6. [Layer 5: Grants & Approvals](#layer-5-grants--approvals)
7. [Layer 6: Audit & Monitoring](#layer-6-audit--monitoring)
8. [Layer 7: Persistent Backends](#layer-7-persistent-backends)
9. [Testing & CI](#testing--ci)
10. [CLI Tools](#cli-tools)

---

## Core Components

### ControlTower

The central enforcement point. All tool calls flow through here.

```python
from tollgate import (
    ControlTower, YamlPolicyEvaluator, ToolRegistry,
    AutoApprover, JsonlAuditSink, InMemoryGrantStore,
    InMemoryRateLimiter, InMemoryCircuitBreaker, NetworkGuard,
    make_verifier
)

tower = ControlTower(
    policy=YamlPolicyEvaluator("policy.yaml"),
    approver=AutoApprover(),
    audit=JsonlAuditSink("audit.jsonl"),

    # Optional security layers
    registry=ToolRegistry("manifest.yaml"),
    grant_store=InMemoryGrantStore(),
    rate_limiter=InMemoryRateLimiter([...]),
    circuit_breaker=InMemoryCircuitBreaker(failure_threshold=5),
    network_guard=NetworkGuard(default="deny", allowlist=[...]),
    verify_fn=make_verifier(b"secret-key"),
)
```

### AgentContext

Identifies who is making the request.

```python
from tollgate import AgentContext

# Direct agent (no delegation)
agent = AgentContext(
    agent_id="my-agent",
    version="1.0.0",
    owner="my-team",
    metadata={"environment": "production"},
)

# Delegated agent (called by another agent)
sub_agent = AgentContext(
    agent_id="sub-agent",
    version="1.0.0",
    owner="my-team",
    delegated_by=("orchestrator", "router"),  # Delegation chain
)

# Properties
sub_agent.delegation_depth  # 2
sub_agent.is_delegated      # True
sub_agent.root_agent        # "orchestrator"
```

### Intent

Describes the goal of the tool call.

```python
from tollgate import Intent

intent = Intent(
    action="fetch_customer_data",
    reason="User requested account balance",
    confidence=0.95,  # Optional: LLM confidence
    metadata={"session_id": "abc123"},
)
```

### ToolRequest

Describes the specific tool call.

```python
from tollgate import ToolRequest, Effect

request = ToolRequest(
    tool="api:customer",
    action="get_balance",
    resource_type="customer_data",
    effect=Effect.READ,  # READ, WRITE, DELETE, NOTIFY, UNKNOWN
    params={"customer_id": "12345"},
    metadata={"source": "user_query"},
    manifest_version="1.0.0",  # Links to registry version
)
```

---

## Layer 1: Identity & Authentication

### Agent Identity Signing

Sign agent contexts with HMAC-SHA256 to prevent spoofing.

```python
from tollgate import sign_agent_context, verify_agent_context, make_verifier

# Sign an agent context
secret = b"your-secret-key"
signed_agent = sign_agent_context(agent, secret)

# Verify manually
is_valid = verify_agent_context(signed_agent, secret)

# Create a verifier function for ControlTower
verifier = make_verifier(secret)
tower = ControlTower(..., verify_fn=verifier)

# Now unsigned or tampered contexts are rejected
```

**How it works:**
- Signature stored in `agent.metadata["_signature"]`
- HMAC-SHA256 over `agent_id + version + owner + sorted(metadata)`
- Tampering any field invalidates the signature

---

## Layer 2: Rate Limiting & Circuit Breaker

### Rate Limiting

Prevent abuse with sliding window rate limits.

```python
from tollgate import InMemoryRateLimiter

limiter = InMemoryRateLimiter([
    # Global limit: 1000 calls per minute
    {
        "agent_id": "*",
        "tool": "*",
        "max_calls": 1000,
        "window_seconds": 60,
    },
    # Write limit: 50 writes per minute
    {
        "agent_id": "*",
        "effect": "write",
        "max_calls": 50,
        "window_seconds": 60,
    },
    # Per-tool limit: 100 calls to MCP tools per minute
    {
        "agent_id": "*",
        "tool": "mcp:*",  # Prefix matching
        "max_calls": 100,
        "window_seconds": 60,
    },
    # Per-agent limit
    {
        "agent_id": "agent-1",
        "tool": "*",
        "max_calls": 500,
        "window_seconds": 60,
    },
])

tower = ControlTower(..., rate_limiter=limiter)
```

**Rule matching:**
- `agent_id: "*"` matches any agent
- `tool: "mcp:*"` matches any tool starting with `mcp:`
- `effect: "write"` matches only WRITE effect
- Multiple rules can apply; all are checked

### Circuit Breaker

Auto-disable failing tools to prevent cascading failures.

```python
from tollgate import InMemoryCircuitBreaker, CircuitState

breaker = InMemoryCircuitBreaker(
    failure_threshold=5,    # Open after 5 consecutive failures
    cooldown_seconds=60,    # Wait 60s before allowing probe
    half_open_max_calls=1,  # 1 probe call in HALF_OPEN state
)

tower = ControlTower(..., circuit_breaker=breaker)

# Monitor circuit states
state = await breaker.get_state("api:weather", "get")
# CircuitState.CLOSED, OPEN, or HALF_OPEN

all_states = await breaker.get_all_states()
# {"api:weather:get": {"state": "open", "failure_count": 5, ...}}

# Reset a circuit
await breaker.reset("api:weather", "get")
```

**State machine:**
```
CLOSED --[5 failures]--> OPEN --[60s cooldown]--> HALF_OPEN
   ^                                                  |
   |                                                  v
   +-----[probe succeeds]<----  CLOSED  <----[probe fails]--> OPEN
```

---

## Layer 3: Policy Evaluation

### YAML Policy Evaluator

Define rules in YAML with powerful matching.

```yaml
# policy.yaml
version: "1.0"
rules:
  # Basic effect matching
  - id: allow_reads
    effect: read
    decision: ALLOW
    reason: "Read operations are safe"

  # Tool + action matching
  - id: deny_delete_users
    tool: "api:users"
    action: "delete"
    decision: DENY
    reason: "Cannot delete users via agent"

  # Agent attribute matching
  - id: allow_trusted_agent
    agent:
      agent_id: "trusted-agent"
    effect: write
    decision: ALLOW
    reason: "Trusted agent can write"

  # Delegation controls
  - id: block_deep_chains
    agent:
      max_delegation_depth: 2
    effect: write
    decision: DENY
    reason: "Delegation chain too deep"

  - id: allow_trusted_delegators
    agent:
      allowed_delegators:
        - "orchestrator"
        - "ci-runner"
    effect: write
    decision: ALLOW
    reason: "Trusted delegation"

  - id: block_compromised_delegators
    agent:
      blocked_delegators:
        - "compromised-agent"
    effect: write
    decision: DENY
    reason: "Blocked delegator in chain"

  # Metadata conditions
  - id: deny_high_risk
    decision: DENY
    reason: "High risk score"
    when:
      risk_score:
        ">=": 0.8

  # Default deny (always last)
  - id: deny_default
    decision: DENY
    reason: "No matching rule"
```

**Delegation policy keys:**
| Key | Description |
|-----|-------------|
| `max_delegation_depth` | Block if chain exceeds N |
| `deny_delegated` | Skip this rule for delegated agents |
| `allowed_delegators` | Only allow if delegated by one of these |
| `blocked_delegators` | Block if delegated by any of these |

---

## Layer 4: Network & Parameter Validation

### NetworkGuard

Global URL policy enforcement.

```python
from tollgate import NetworkGuard

guard = NetworkGuard(
    default="deny",  # or "allow"
    allowlist=[
        {"pattern": "https://api.github.com/*"},
        {"pattern": "https://api.openai.com/*"},
        {"pattern": "https://*.internal.company.com/*"},
    ],
    blocklist=[
        {"pattern": "http://*"},           # Block insecure
        {"pattern": "*.malware.com/*"},    # Block known bad
        {"pattern": "10.*"},               # Block internal IPs
    ],
    param_fields_to_check=["url", "endpoint", "webhook"],  # Which params to check
)

tower = ControlTower(..., network_guard=guard)
```

**Evaluation order:**
1. Check blocklist first (block if match)
2. Check allowlist (allow if match)
3. Apply default (deny or allow)

### Parameter Schema Validation

Define JSON Schema for tool parameters in your manifest.

```yaml
# manifest.yaml
version: "1.0.0"
tools:
  "api:write_file":
    effect: write
    resource_type: file
    params_schema:
      type: object
      required:
        - path
        - content
      properties:
        path:
          type: string
          pattern: "^/safe/"      # Must start with /safe/
          maxLength: 255
        content:
          type: string
          maxLength: 1048576      # 1MB max
        mode:
          type: string
          enum: ["overwrite", "append"]
```

**Supported schema keywords:**
- `type`: string, integer, number, boolean, array, object
- `required`: Required field names
- `properties`: Nested schemas
- `pattern`: Regex pattern (strings)
- `minLength`, `maxLength`: String length
- `minimum`, `maximum`: Numeric range
- `enum`: Allowed values
- `items`: Array item schema

### URL Constraints (Per-Tool)

Define URL restrictions per tool in the manifest.

```yaml
# manifest.yaml
tools:
  "api:fetch":
    effect: read
    resource_type: url
    constraints:
      allowed_url_patterns:
        - "https://api.github.com/*"
        - "https://arxiv.org/*"
      blocked_url_patterns:
        - "http://*"
        - "*.internal.*"
      param_constraints:
        format:
          allowed_values: ["json", "xml"]
```

---

## Layer 5: Grants & Approvals

### Session Grants

Pre-authorize specific actions to bypass human approval.

```python
from tollgate import Grant, InMemoryGrantStore, Effect
import time

grant_store = InMemoryGrantStore()
tower = ControlTower(..., grant_store=grant_store)

# Create a grant
grant = Grant(
    agent_id="my-agent",      # or None for any agent
    effect=Effect.WRITE,       # or None for any effect
    tool="mcp:*",              # Prefix match, or None for any
    action=None,               # Any action
    resource_type=None,        # Any resource
    expires_at=time.time() + 3600,  # 1 hour
    granted_by="admin@company.com",
    created_at=time.time(),
    reason="Approved for batch processing",
)

grant_id = await grant_store.create_grant(grant)

# List active grants
grants = await grant_store.list_active_grants(agent_id="my-agent")

# Check usage
usage = await grant_store.get_usage_count(grant_id)

# Revoke a grant
await grant_store.revoke_grant(grant_id)

# Cleanup expired grants
removed = await grant_store.cleanup_expired()
```

### Approvers

Handle human-in-the-loop approvals.

```python
from tollgate import AutoApprover, CliApprover, AsyncQueueApprover

# Auto-approve reads, deny writes (for testing)
approver = AutoApprover()

# Interactive CLI approval
approver = CliApprover(show_emojis=True, timeout=300)

# Async queue-based approval (for web UIs)
from tollgate import InMemoryApprovalStore

approval_store = InMemoryApprovalStore()
approver = AsyncQueueApprover(
    store=approval_store,
    timeout=3600,
    default_outcome=ApprovalOutcome.DENIED,
)

# External system can approve via:
await approval_store.set_decision(
    approval_id="...",
    outcome=ApprovalOutcome.APPROVED,
    decided_by="admin@company.com",
    decided_at=time.time(),
    request_hash="...",
)
```

---

## Layer 6: Audit & Monitoring

### Audit Sinks

Log every decision for compliance and debugging.

```python
from tollgate import JsonlAuditSink, WebhookAuditSink, CompositeAuditSink

# File-based JSON Lines
file_sink = JsonlAuditSink("audit.jsonl")

# Webhook alerts for security events
webhook_sink = WebhookAuditSink(
    url="https://alerts.company.com/tollgate",
    alert_outcomes=frozenset({"blocked", "approval_denied", "failed"}),
)

# Combine multiple sinks
composite = CompositeAuditSink([file_sink, webhook_sink])

tower = ControlTower(..., audit=composite)
```

### Anomaly Detection

Detect unusual patterns in tool usage.

```python
from tollgate import AnomalyDetector, CompositeAuditSink

detector = AnomalyDetector(
    window_seconds=300,       # 5-minute sliding window
    z_score_threshold=3.0,    # Alert at 3 standard deviations
    min_samples=10,           # Need 10+ samples before alerting
    baseline_interval=60,     # Sample baseline every 60s
    alert_callback=lambda alert: send_to_slack(alert),
)

# Use as an audit sink
composite = CompositeAuditSink([file_sink, detector])

# Detection types:
# - rate_spike: Unusual call frequency
# - error_burst: Sudden increase in failures
# - deny_surge: Unusual number of denials
# - unusual_tool: Agent calling new tool for first time
```

### Context Integrity Monitor

Detect unauthorized modifications to agent context.

```python
from tollgate import ContextIntegrityMonitor

monitor = ContextIntegrityMonitor(
    immutable_fields={"system_prompt", "tool_permissions", "security_level"},
    max_snapshots=1000,
    alert_callback=lambda result: log_security_event(result),
)

# At start of each turn
context = {
    "system_prompt": "You are a helpful assistant...",
    "tool_permissions": ["read", "write"],
    "memory": {"conversation": [...]},
}
monitor.snapshot("agent-1", "turn-5", context)

# Before processing
result = monitor.verify("agent-1", "turn-5", current_context)

if not result.is_valid:
    print(f"ALERT: Context tampered!")
    print(f"Changed: {result.changed_fields}")
    print(f"Added: {result.added_fields}")
    print(f"Removed: {result.removed_fields}")
```

---

## Layer 7: Persistent Backends

### SQLite (Zero Dependencies)

Best for single-process deployments.

```python
from tollgate.backends import SQLiteGrantStore, SQLiteApprovalStore

# Separate databases
grant_store = SQLiteGrantStore("grants.db")
approval_store = SQLiteApprovalStore("approvals.db")

# Or shared database with different tables
grant_store = SQLiteGrantStore("tollgate.db", table_name="grants")
approval_store = SQLiteApprovalStore("tollgate.db", table_name="approvals")

# In-memory for testing
grant_store = SQLiteGrantStore(":memory:")

# Close when done
grant_store.close()
```

### Redis (Distributed)

Best for multi-process and multi-host deployments.

```bash
pip install tollgate[redis]
```

```python
from tollgate.backends import RedisGrantStore, RedisApprovalStore

# From URL
grant_store = RedisGrantStore(redis_url="redis://localhost:6379/0")
approval_store = RedisApprovalStore(redis_url="redis://localhost:6379/0")

# Or with existing client
import redis.asyncio as aioredis
client = aioredis.from_url("redis://localhost:6379/0")
grant_store = RedisGrantStore(redis_client=client, key_prefix="myapp:grant:")

# Close when done
await grant_store.close()
```

**Redis features:**
- Automatic TTL on grants (uses Redis EXPIRE)
- Pub/sub for approval notifications (no polling)
- Index sets for efficient listing

---

## Testing & CI

### Policy Testing Framework

Test policies declaratively to prevent regressions.

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
      tool: "api:data"
      action: "get"
      resource_type: "data"
      effect: "read"
      manifest_version: "1.0"
    expected:
      decision: "ALLOW"
      policy_id: "allow_reads"

  - name: "Block deep delegation"
    agent:
      agent_id: "sub-agent"
      delegated_by: ["a", "b", "c"]  # Depth 3
    tool_request:
      effect: "write"
    expected:
      decision: "DENY"
      reason_contains: "too deep"
```

```python
from tollgate import PolicyTestRunner

# From files
runner = PolicyTestRunner("policy.yaml", "test_scenarios.yaml")

# Or programmatic
runner = PolicyTestRunner("policy.yaml", scenarios=[...])

# Run tests
results = runner.run()

print(results.summary())
# ============================================================
#   Policy Test Results: 5/5 passed
# ============================================================
#   [PASS] Allow read operations
#   [PASS] Block deep delegation
#   ...

assert results.all_passed  # For CI
```

---

## CLI Tools

### Policy Testing

```bash
# Basic usage
tollgate test-policy policy.yaml --scenarios test_scenarios.yaml

# Quiet mode (only show failures)
tollgate test-policy policy.yaml -s scenarios.yaml --quiet

# Exit codes:
# 0 = All tests passed
# 1 = Some tests failed
# 2 = Configuration error
```

### Manifest Signing

```python
from tollgate import sign_manifest, verify_manifest, get_manifest_hash

# Sign at build time
sign_manifest("manifest.yaml", secret_key=b"build-secret")
# Creates manifest.yaml.sig

# Verify at runtime
is_valid = verify_manifest("manifest.yaml", secret_key=b"build-secret")

# Get content hash for audit
content_hash = get_manifest_hash("manifest.yaml")
```

---

## Complete Example

```python
import asyncio
import time
from tollgate import (
    # Core
    ControlTower, AgentContext, Intent, ToolRequest, Effect,
    # Policy & Registry
    YamlPolicyEvaluator, ToolRegistry,
    # Security layers
    InMemoryRateLimiter, InMemoryCircuitBreaker, NetworkGuard,
    sign_agent_context, make_verifier, sign_manifest,
    # Grants & Approvals
    InMemoryGrantStore, Grant, CliApprover,
    # Audit
    JsonlAuditSink, WebhookAuditSink, CompositeAuditSink,
    AnomalyDetector, ContextIntegrityMonitor,
)

async def main():
    # Sign manifest at build time (do this in CI)
    secret = b"build-secret"
    sign_manifest("manifest.yaml", secret_key=secret)

    # Setup all security layers
    registry = ToolRegistry("manifest.yaml", signing_key=secret)
    policy = YamlPolicyEvaluator("policy.yaml")

    rate_limiter = InMemoryRateLimiter([
        {"agent_id": "*", "tool": "*", "max_calls": 100, "window_seconds": 60},
    ])

    circuit_breaker = InMemoryCircuitBreaker(
        failure_threshold=5,
        cooldown_seconds=60,
    )

    network_guard = NetworkGuard(
        default="deny",
        allowlist=[{"pattern": "https://api.safe.com/*"}],
    )

    grant_store = InMemoryGrantStore()

    # Audit pipeline
    file_sink = JsonlAuditSink("audit.jsonl")
    detector = AnomalyDetector(alert_callback=print)
    audit = CompositeAuditSink([file_sink, detector])

    # Context integrity
    context_monitor = ContextIntegrityMonitor()

    # Create tower
    agent_secret = b"agent-secret"
    tower = ControlTower(
        policy=policy,
        approver=CliApprover(),
        audit=audit,
        registry=registry,
        grant_store=grant_store,
        rate_limiter=rate_limiter,
        circuit_breaker=circuit_breaker,
        network_guard=network_guard,
        verify_fn=make_verifier(agent_secret),
    )

    # Create signed agent
    agent = sign_agent_context(
        AgentContext(agent_id="my-agent", version="1.0", owner="my-team"),
        agent_secret,
    )

    # Snapshot context
    context_monitor.snapshot(agent.agent_id, "turn-1", {
        "system_prompt": "You are helpful",
        "tool_permissions": ["read"],
    })

    # Create request
    intent = Intent(action="fetch_data", reason="User request")
    request = ToolRequest(
        tool="api:data",
        action="get",
        resource_type="data",
        effect=Effect.READ,
        params={"url": "https://api.safe.com/data"},
        manifest_version="1.0.0",
    )

    # Execute
    result = await tower.execute_async(
        agent, intent, request,
        lambda: {"data": "example"},
    )

    print(f"Result: {result}")

asyncio.run(main())
```

---

## API Reference

For complete API documentation, see the source code and type hints in `src/tollgate/`.

Key modules:
- `tollgate.tower` - ControlTower
- `tollgate.types` - Core data types
- `tollgate.policy` - Policy evaluation
- `tollgate.registry` - Tool registry
- `tollgate.grants` - Grant management
- `tollgate.approvals` - Approval workflows
- `tollgate.audit` - Audit sinks
- `tollgate.rate_limiter` - Rate limiting
- `tollgate.circuit_breaker` - Circuit breaker
- `tollgate.network_guard` - URL filtering
- `tollgate.verification` - Agent signing
- `tollgate.manifest_signing` - Manifest integrity
- `tollgate.context_monitor` - Context integrity
- `tollgate.anomaly_detector` - Anomaly detection
- `tollgate.policy_testing` - Policy testing
- `tollgate.backends` - Persistent stores
