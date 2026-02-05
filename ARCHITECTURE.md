# Tollgate Architecture

This document explains Tollgate's architecture — how its components fit together and where they sit in the lifecycle of an AI agent tool call.

---

## The Problem

When an AI agent calls a tool — reading a file, sending an email, querying a database — there is no built-in mechanism to verify **who** is calling, **why** they're calling, or whether the call should be **allowed**. Tollgate is a runtime enforcement layer that sits between the agent and the tool, making every call go through a security checkpoint.

---

## Core Idea: Identity + Intent + Policy

Every tool call in Tollgate is evaluated against three questions:

```
 ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
 │    WHO?      │     │    WHY?      │     │    WHAT?     │
 │              │     │              │     │              │
 │ AgentContext │     │   Intent     │     │ ToolRequest  │
 │              │     │              │     │              │
 │ agent_id     │     │ action       │     │ tool         │
 │ version      │     │ reason       │     │ action       │
 │ owner        │     │ confidence   │     │ effect       │
 │ delegated_by │     │              │     │ params       │
 └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  ControlTower   │
                    │   (Enforcer)    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    Decision     │
                    │                 │
                    │ ALLOW │ ASK │   │
                    │      DENY      │
                    └─────────────────┘
```

---

## The Three Core Entities

### AgentContext — "Who is calling?"

Represents the agent making the request. Immutable and optionally signed with HMAC-SHA256.

```python
AgentContext(
    agent_id="weather-bot",        # Unique identifier
    version="2.1.0",               # Agent version
    owner="platform-team",         # Responsible team
    delegated_by=("orchestrator",) # Who delegated to this agent
)
```

**Key properties:**
- `delegation_depth` — How many agents are in the delegation chain
- `is_delegated` — Whether this agent was called by another agent
- `root_agent` — The original agent that started the chain

### Intent — "Why are they calling?"

Describes the agent's stated goal. This is the agent's claim about what it's trying to accomplish.

```python
Intent(
    action="get_weather",                # What the agent wants to do
    reason="User asked about London",    # Why
    confidence=0.95,                     # LLM confidence (optional)
)
```

### ToolRequest — "What exactly are they doing?"

The specific tool call being made. The `effect` field is the most important — it comes from the trusted Tool Registry, not the agent.

```python
ToolRequest(
    tool="api:weather",           # Tool identifier
    action="get",                 # Action on the tool
    effect=Effect.READ,           # READ | WRITE | DELETE | NOTIFY | UNKNOWN
    resource_type="weather",      # What kind of resource
    params={"city": "London"},    # Parameters
    manifest_version="1.0.0",     # Links to trusted registry
)
```

**Effects** determine the risk level:

| Effect | Risk | Default Policy |
|--------|------|----------------|
| `READ` | Low | Typically ALLOW |
| `WRITE` | Medium | Typically ASK |
| `DELETE` | High | Typically ASK or DENY |
| `NOTIFY` | Medium | Typically ALLOW |
| `UNKNOWN` | Highest | Always DENY |

---

## ControlTower — The Enforcer

The `ControlTower` is the central class. It orchestrates all security checks and makes the final decision. You configure it once with all the security layers you want, then route every tool call through it.

```python
tower = ControlTower(
    # Required
    policy=YamlPolicyEvaluator("policy.yaml"),
    approver=CliApprover(),
    audit=JsonlAuditSink("audit.jsonl"),

    # Optional security layers
    registry=ToolRegistry("manifest.yaml"),
    grant_store=InMemoryGrantStore(),
    rate_limiter=InMemoryRateLimiter([...]),
    circuit_breaker=InMemoryCircuitBreaker(...),
    network_guard=NetworkGuard(...),
    verify_fn=make_verifier(secret),
)
```

---

## The Enforcement Pipeline

When `tower.execute_async()` is called, the request goes through these checks **in order**. Any check can halt the pipeline.

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                    ENFORCEMENT PIPELINE                         │
 │                                                                 │
 │  ┌─────────────────────────────────────────────────────────┐   │
 │  │ 1. IDENTITY VERIFICATION                                │   │
 │  │    verify_fn(agent_ctx) → signed? not tampered?         │   │
 │  │    ✗ → TollgateDenied                                   │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │ ✓                                      │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 2. CIRCUIT BREAKER                                      │   │
 │  │    Is this tool in OPEN state? (too many recent fails)   │   │
 │  │    ✗ → TollgateDenied                                   │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │ ✓                                      │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 3. RATE LIMITING                                        │   │
 │  │    Sliding window check per agent/tool/effect            │   │
 │  │    ✗ → TollgateRateLimited (with retry_after)           │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │ ✓                                      │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 4. POLICY EVALUATION                                    │   │
 │  │    YAML rules: effect, tool, agent, delegation, metadata │   │
 │  │    → ALLOW │ ASK │ DENY                                 │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │                                        │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 5. NETWORK GUARD (if not DENY)                          │   │
 │  │    Check all URL params against global allowlist/blocklist│   │
 │  │    ✗ → TollgateConstraintViolation                      │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │                                        │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 6. PARAMETER VALIDATION (if not DENY)                   │   │
 │  │    JSON Schema: type, required, pattern, enum, range     │   │
 │  │    ✗ → TollgateDenied                                   │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │                                        │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 7. PER-TOOL CONSTRAINTS (if not DENY)                   │   │
 │  │    URL patterns, param value constraints                 │   │
 │  │    ✗ → TollgateConstraintViolation                      │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │                                        │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 8. DECISION ROUTING                                     │   │
 │  │                                                          │   │
 │  │    DENY  → Log + TollgateDenied                         │   │
 │  │                                                          │   │
 │  │    ASK   → Check grants first:                          │   │
 │  │            ├─ Grant found? → Execute (skip approval)    │   │
 │  │            └─ No grant?   → Request human approval      │   │
 │  │                             ├─ Approved → Execute       │   │
 │  │                             ├─ Denied   → TollgateApprovalDenied│
 │  │                             └─ Deferred → TollgateDeferred│   │
 │  │                                                          │   │
 │  │    ALLOW → Execute                                      │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │                                        │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 9. TOOL EXECUTION                                       │   │
 │  │    Run the actual tool function                          │   │
 │  │    ├─ Success → Record in circuit breaker               │   │
 │  │    └─ Failure → Record failure in circuit breaker        │   │
 │  └─────────────────────┬───────────────────────────────────┘   │
 │                        │                                        │
 │  ┌─────────────────────▼───────────────────────────────────┐   │
 │  │ 10. AUDIT LOGGING                                       │   │
 │  │     Every outcome is logged with full context:           │   │
 │  │     correlation_id, request_hash, decision, outcome,     │   │
 │  │     agent, intent, tool_request, timestamps              │   │
 │  └─────────────────────────────────────────────────────────┘   │
 │                                                                 │
 └─────────────────────────────────────────────────────────────────┘
```

---

## Component Map

Here's how every component relates to the pipeline:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          CONFIGURATION                                 │
│                                                                        │
│  manifest.yaml        policy.yaml         secrets                      │
│  ┌────────────┐      ┌────────────┐      ┌──────────────────────┐     │
│  │ Tools:     │      │ Rules:     │      │ Agent signing key    │     │
│  │  effect    │      │  effect    │      │ Manifest signing key │     │
│  │  schema    │      │  decision  │      └──────────────────────┘     │
│  │  constraints│     │  delegation│                                    │
│  └─────┬──────┘      └─────┬──────┘                                   │
│        │                   │                                           │
│        ▼                   ▼                                           │
│  ┌────────────┐     ┌──────────────────┐                              │
│  │ToolRegistry│     │YamlPolicyEvaluator│                             │
│  └────────────┘     └──────────────────┘                              │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│                        RUNTIME ENFORCEMENT                             │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │                      ControlTower                             │     │
│  │                                                               │     │
│  │  Pre-execution guards:                                        │     │
│  │  ┌──────────┐ ┌───────────────┐ ┌──────────────┐            │     │
│  │  │verify_fn │ │CircuitBreaker │ │ RateLimiter  │            │     │
│  │  └──────────┘ └───────────────┘ └──────────────┘            │     │
│  │                                                               │     │
│  │  Policy + validation:                                         │     │
│  │  ┌─────────────┐ ┌────────────┐ ┌──────────────┐            │     │
│  │  │PolicyEvaluator│ │NetworkGuard│ │ToolRegistry │            │     │
│  │  └─────────────┘ └────────────┘ └──────────────┘            │     │
│  │                                                               │     │
│  │  Approval flow:                                               │     │
│  │  ┌────────────┐ ┌──────────┐                                 │     │
│  │  │ GrantStore │ │ Approver │                                 │     │
│  │  └────────────┘ └──────────┘                                 │     │
│  └──────────────────────────────────────────────────────────────┘     │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│                        POST-EXECUTION                                  │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │  Audit Pipeline                                               │     │
│  │  ┌────────────────┐ ┌──────────────┐ ┌─────────────────┐    │     │
│  │  │ JsonlAuditSink │ │WebhookAudit  │ │AnomalyDetector  │    │     │
│  │  │ (file logging) │ │(alerts)      │ │(pattern analysis)│    │     │
│  │  └────────────────┘ └──────────────┘ └─────────────────┘    │     │
│  │         ↑                  ↑                 ↑                │     │
│  │         └──────────────────┼─────────────────┘                │     │
│  │                   ┌────────┴────────┐                         │     │
│  │                   │CompositeAuditSink│                        │     │
│  │                   └─────────────────┘                         │     │
│  └──────────────────────────────────────────────────────────────┘     │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │  Monitoring (out-of-band)                                     │     │
│  │  ┌────────────────────────┐ ┌──────────────────────────┐     │     │
│  │  │ContextIntegrityMonitor │ │ PolicyTestRunner (CI)    │     │     │
│  │  │(memory poisoning check)│ │ (policy regression test) │     │     │
│  │  └────────────────────────┘ └──────────────────────────┘     │     │
│  └──────────────────────────────────────────────────────────────┘     │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│                       PERSISTENT STORAGE                               │
│                                                                        │
│  In-Memory (dev/test)           SQLite (single-process)                │
│  ┌───────────────────┐         ┌──────────────────┐                   │
│  │InMemoryGrantStore │         │SQLiteGrantStore   │                   │
│  │InMemoryApprovalSt.│         │SQLiteApprovalStore│                   │
│  └───────────────────┘         └──────────────────┘                   │
│                                                                        │
│  Redis (distributed)                                                   │
│  ┌──────────────────┐                                                  │
│  │RedisGrantStore   │                                                  │
│  │RedisApprovalStore│                                                  │
│  └──────────────────┘                                                  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Where Tollgate Fits in the Agent Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                     AI AGENT LIFECYCLE                           │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  User    │───▶│   LLM    │───▶│ Agent    │───▶│ Tool     │  │
│  │  Input   │    │ Reasoning│    │ Decision │    │ Execution│  │
│  └──────────┘    └──────────┘    └────┬─────┘    └──────────┘  │
│                                       │                          │
│                                       │ "I need to call          │
│                                       │  api:weather.get"        │
│                                       │                          │
│                               ┌───────▼───────┐                 │
│                               │               │                 │
│                               │   TOLLGATE    │                 │
│                               │               │                 │
│                               │  WHO + WHY +  │                 │
│                               │  WHAT → OK?   │                 │
│                               │               │                 │
│                               └───────┬───────┘                 │
│                                       │                          │
│                              ┌────────┼────────┐                │
│                              │        │        │                │
│                           ALLOW     ASK      DENY               │
│                              │        │        │                │
│                              ▼        ▼        ▼                │
│                           Execute  Human    Block               │
│                            Tool   Review   + Log                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

Tollgate operates at the **tool-call boundary** — the moment an agent decides to call an external tool. It does not interfere with the LLM's reasoning or the agent's planning. It only enforces rules at the point of action.

### Multi-Agent Scenarios

In multi-agent systems, Tollgate tracks the delegation chain:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Orchestrator │────▶│   Router     │────▶│   Worker     │
│              │     │              │     │              │
│ agent_id:    │     │ agent_id:    │     │ agent_id:    │
│ "orch"       │     │ "router"     │     │ "worker"     │
└──────────────┘     └──────────────┘     │              │
                                          │ delegated_by:│
                                          │ ("orch",     │
                                          │  "router")   │
                                          └──────┬───────┘
                                                 │
                                          ┌──────▼───────┐
                                          │  ControlTower │
                                          │               │
                                          │ Checks:       │
                                          │ • depth ≤ 2?  │
                                          │ • "orch" in   │
                                          │   allowed?    │
                                          │ • "router" in │
                                          │   blocked?    │
                                          └───────────────┘
```

---

## Policy System

Policies are YAML files with ordered rules. First match wins.

```yaml
rules:
  - id: allow_reads
    effect: read              # Match by effect
    decision: ALLOW

  - id: trusted_delegation
    agent:
      allowed_delegators:     # Only these can delegate
        - "orchestrator"
      max_delegation_depth: 2 # Chain length limit
    effect: write
    decision: ALLOW

  - id: ask_writes
    effect: write
    decision: ASK             # Human must approve

  - id: deny_default
    decision: DENY            # Catch-all: fail closed
```

**Matching capabilities:**
- `effect` — READ, WRITE, DELETE, NOTIFY
- `tool`, `action`, `resource_type` — Exact match
- `agent.agent_id`, `agent.version` — Agent attributes
- `agent.allowed_delegators` — Delegation trust list
- `agent.blocked_delegators` — Delegation block list
- `agent.max_delegation_depth` — Chain depth limit
- `agent.deny_delegated` — Skip rule for delegated agents
- `when` — Metadata conditions with operators (`>=`, `<=`, `==`, `!=`)

---

## Approvals & Grants

When a policy returns `ASK`, two mechanisms can resolve it:

### Grants (Pre-approvals)

Grants are pre-authorized permissions that bypass the human approval step. They support wildcards and expiration.

```python
Grant(
    agent_id="batch-agent",     # or None for any agent
    effect=Effect.WRITE,        # or None for any effect
    tool="api:*",               # Prefix matching
    expires_at=time.time()+3600 # 1 hour
)
```

### Approvers

If no grant matches, an `Approver` handles the request:

| Approver | Use Case |
|----------|----------|
| `AutoApprover` | Testing — auto-approves READs, denies everything else |
| `CliApprover` | Development — interactive terminal prompt |
| `AsyncQueueApprover` | Production — external system decides via API |

---

## Audit Pipeline

Every decision is logged as a structured `AuditEvent`:

```
┌─────────────────────────────────────────────┐
│ AuditEvent                                   │
│                                              │
│ timestamp, correlation_id, request_hash      │
│ agent, intent, tool_request                  │
│ decision (ALLOW/ASK/DENY)                    │
│ outcome (EXECUTED/BLOCKED/FAILED)            │
│ grant_id (if grant was used)                 │
│ approval_id (if approval was requested)      │
│ result_summary (truncated)                   │
│ schema_version: "1.0"                        │
└──────────────────┬──────────────────────────┘
                   │
          ┌────────┼────────┐
          ▼        ▼        ▼
    ┌──────────┐ ┌──────┐ ┌─────────────────┐
    │  JSONL   │ │Webhook│ │AnomalyDetector  │
    │  file    │ │alerts │ │                 │
    │          │ │(BLOCK,│ │ rate_spike      │
    │ append-  │ │ DENY, │ │ error_burst     │
    │ only log │ │ FAIL) │ │ deny_surge      │
    └──────────┘ └──────┘ │ unusual_tool    │
                          └─────────────────┘
```

**Sensitive parameters** (password, token, secret, api_key) are **redacted** before logging, not before enforcement.

---

## Monitoring Components

These components operate **outside** the main enforcement pipeline:

### ContextIntegrityMonitor

Detects unauthorized changes to agent context between turns. Takes SHA-256 snapshots and verifies immutable fields haven't changed.

```
Turn 1: snapshot(context)  →  { system_prompt: sha256("..."), ... }
Turn 2: verify(context)    →  ✓ Valid
Turn 3: verify(context)    →  ✗ security_level changed! ALERT
```

### AnomalyDetector

Plugs into the audit pipeline as an `AuditSink`. Analyzes patterns using z-score statistics over sliding windows.

| Alert Type | What It Detects |
|------------|-----------------|
| `rate_spike` | Call frequency suddenly increases |
| `error_burst` | Sudden increase in tool failures |
| `deny_surge` | Unusual number of policy denials |
| `unusual_tool` | Agent calling a tool it never used before |

### PolicyTestRunner

Runs declarative test scenarios against policies in CI. Catches regressions before deployment.

```bash
tollgate test-policy policy.yaml --scenarios test_scenarios.yaml
# Exit code 0 = all pass, 1 = failures
```

---

## Framework Integrations

Tollgate integrates with agent frameworks by wrapping their tool-calling mechanisms:

```
┌─────────────────────────────────────────────────────────────┐
│                  FRAMEWORK ADAPTERS                          │
│                                                              │
│  ┌──────────────────┐    ┌──────────────────┐               │
│  │ MCP              │    │ Strands          │               │
│  │                  │    │                  │               │
│  │ TollgateMCPClient│    │ guard_tools()    │               │
│  │ wraps base client│    │ wraps tool list  │               │
│  └────────┬─────────┘    └────────┬─────────┘               │
│           │                       │                          │
│           └───────────┬───────────┘                          │
│                       ▼                                      │
│              ┌─────────────────┐                             │
│              │  ControlTower   │                             │
│              │  .execute_async │                             │
│              └─────────────────┘                             │
│                                                              │
│  ┌──────────────────┐    ┌──────────────────┐               │
│  │ LangChain        │    │ OpenAI           │               │
│  │                  │    │                  │               │
│  │ guard_tools()    │    │ OpenAIToolRunner │               │
│  │ wraps LC tools   │    │ wraps tool_calls│               │
│  └──────────────────┘    └──────────────────┘               │
└─────────────────────────────────────────────────────────────┘
```

Each adapter:
1. Intercepts the tool call
2. Resolves tool name to registry format (e.g., `mcp:server.tool`)
3. Builds `AgentContext`, `Intent`, `ToolRequest`
4. Routes through `ControlTower.execute_async()`
5. Returns result or raises Tollgate exception

---

## Exception Hierarchy

```
TollgateError (base)
├── TollgateDenied              — Policy says no
├── TollgateApprovalDenied      — Human said no (or timeout)
├── TollgateDeferred            — Approval pending (async)
├── TollgateRateLimited         — Too many calls (includes retry_after)
└── TollgateConstraintViolation — Parameter or URL constraint failed
```

Every exception carries a descriptive `reason` so the agent (or operator) understands what went wrong.

---

## Storage Backends

| Backend | Best For | Dependencies | Features |
|---------|----------|-------------|----------|
| `InMemory*` | Testing, development | None | Fast, no persistence |
| `SQLite*` | Single-process production | None (stdlib) | WAL mode, persistent |
| `Redis*` | Distributed production | `redis[hiredis]` | TTL, pub/sub, multi-host |

All backends implement the same `GrantStore` and `ApprovalStore` protocols, so you can swap them without changing any other code.

---

## Design Principles

1. **Fail closed** — Unknown effects, missing rules, and unverified agents all result in DENY
2. **Developer controls metadata** — Tool effects come from the registry, not from agents
3. **Deterministic decisions** — No LLM in the enforcement loop; policies are pure logic
4. **Defense in depth** — Multiple independent layers; no single point of failure
5. **Async-first** — All enforcement is async; sync wrapper available for convenience
6. **Protocol-based** — Every component is a pluggable protocol; swap implementations freely
7. **Audit everything** — Every outcome (allow, deny, execute, fail) is logged with full context
8. **Least agency** — Grant only the minimum autonomy needed for safe, bounded tasks
