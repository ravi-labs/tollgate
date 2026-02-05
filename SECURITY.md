# Security Policy

## Supported Versions

Only the latest version of `tollgate` is supported for security updates.

## Security Architecture

Tollgate implements a **7-layer defense-in-depth** security model:

```
Layer 1: Identity Verification (HMAC-SHA256 agent signing)
Layer 2: Rate Limiting & Circuit Breaker
Layer 3: Policy Evaluation (with delegation controls)
Layer 4: Network Guard & Parameter Validation
Layer 5: Grants & Approvals
Layer 6: Audit & Monitoring
Layer 7: Persistent Backends
```

## Core Security Guarantees

### 1. Trusted Tool Registry

Tollgate enforces that tool metadata (`effect`, `resource_type`) must originate from a developer-controlled **Tool Registry**. Agent-provided claims about a tool's impact are treated as untrusted.

**Manifest Signing (v1.3+)**: Manifests can be cryptographically signed at build time using HMAC-SHA256. The `ToolRegistry` rejects tampered manifests when a signing key is provided.

```python
from tollgate import sign_manifest, ToolRegistry

# At build time
sign_manifest("manifest.yaml", secret_key=b"build-secret")

# At runtime (rejects tampering)
registry = ToolRegistry("manifest.yaml", signing_key=b"build-secret")
```

### 2. Deterministic Enforcement

All policy decisions are deterministic. We strongly advise against using non-deterministic models (LLMs) to make final gating decisions, as this introduces potential jailbreak vectors.

### 3. Approval Integrity

Approval requests are cryptographically bound to a `request_hash` (fingerprint of the agent, intent, tool, parameters, and trusted metadata). If the request is modified or the policy changes during a pending approval, the hash will mismatch, requiring re-evaluation.

### 4. Safe Defaults

By default, any tool with an unknown effect or resource type will be subject to a `DENY` decision. No heuristic inference will ever result in an `ALLOW` by default.

### 5. Agent Identity Verification (v1.2+)

Agent contexts can be signed with HMAC-SHA256 to prevent spoofing:

```python
from tollgate import sign_agent_context, make_verifier, ControlTower

secret = b"agent-secret"
signed_agent = sign_agent_context(agent, secret)

tower = ControlTower(
    ...,
    verify_fn=make_verifier(secret),  # Rejects unsigned/tampered agents
)
```

### 6. Rate Limiting (v1.2+)

Sliding window rate limits prevent abuse:

```python
from tollgate import InMemoryRateLimiter

limiter = InMemoryRateLimiter([
    {"agent_id": "*", "tool": "*", "max_calls": 100, "window_seconds": 60},
    {"agent_id": "*", "effect": "write", "max_calls": 10, "window_seconds": 60},
])
```

### 7. Circuit Breaker (v1.3+)

Auto-disable failing tools to prevent cascading failures:

```python
from tollgate import InMemoryCircuitBreaker

breaker = InMemoryCircuitBreaker(
    failure_threshold=5,    # Open after 5 consecutive failures
    cooldown_seconds=60,    # Wait 60s before probe
)
```

### 8. Network Security (v1.3+)

Global URL policy enforcement:

```python
from tollgate import NetworkGuard

guard = NetworkGuard(
    default="deny",
    allowlist=[{"pattern": "https://api.trusted.com/*"}],
    blocklist=[{"pattern": "http://*"}],  # Block insecure
)
```

### 9. Multi-Agent Delegation Security (v1.4+)

Track and control delegation chains to prevent confused deputy attacks:

```python
from tollgate import AgentContext

sub_agent = AgentContext(
    agent_id="sub-agent",
    delegated_by=("orchestrator", "router"),  # Tracked chain
)
```

Policy rules can enforce:
- `max_delegation_depth`: Block if chain exceeds N
- `deny_delegated`: Skip rule for delegated agents
- `allowed_delegators`: Only allow specific delegators
- `blocked_delegators`: Block specific delegators

### 10. Context Integrity Monitoring (v1.4+)

Detect unauthorized modifications to agent context:

```python
from tollgate import ContextIntegrityMonitor

monitor = ContextIntegrityMonitor()
monitor.snapshot("agent-1", "turn-1", context)

# Later...
result = monitor.verify("agent-1", "turn-1", current_context)
if not result.is_valid:
    # Context was tampered!
```

### 11. Anomaly Detection (v1.4+)

Real-time anomaly detection on audit streams:

```python
from tollgate import AnomalyDetector

detector = AnomalyDetector(
    z_score_threshold=3.0,  # Alert at 3 standard deviations
    alert_callback=security_team_alert,
)
```

Detects:
- **Rate spikes**: Unusual call frequency
- **Error bursts**: Sudden increase in failures
- **Deny surges**: Unusual number of denials
- **Unusual tools**: Agent calling new tools

## OWASP Top 10 for Agentic Applications (2026)

The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) is a peer-reviewed framework released by the OWASP GenAI Security Project identifying the most critical security risks facing autonomous AI agent systems. Below is each risk, what it means, and how Tollgate addresses it.

---

### ASI01 — Agent Goal Hijack

Manipulation of instructions, inputs, or external content to redirect an agent's objectives. Prompt injection and indirect prompt injection can cause agents to silently deviate from their intended goals.

| | |
|---|---|
| **Tollgate Coverage** | Partial |
| **Features** | Deterministic policy evaluation (no LLM in the loop), delegation controls (`allowed_delegators`, `blocked_delegators`), context integrity monitoring to detect mid-session tampering |
| **Gaps** | Tollgate operates at the tool-call layer; prompt-level hijacking must be addressed upstream in the LLM or orchestrator |

---

### ASI02 — Tool Misuse & Exploitation

Agents misusing legitimate tools due to prompt manipulation, misalignment, or unsafe delegation. Ambiguous inputs can cause agents to call tools with destructive parameters or chain tools in unexpected sequences.

| | |
|---|---|
| **Tollgate Coverage** | Strong |
| **Features** | `ToolRegistry` with developer-controlled metadata, JSON Schema `params_schema` validation, per-tool URL constraints (`allowed_url_patterns`, `blocked_url_patterns`), `NetworkGuard` for global URL enforcement, effect-based policy rules (READ/WRITE/DELETE/NOTIFY), rate limiting per tool/effect |

---

### ASI03 — Identity & Privilege Abuse

Exploiting inherited credentials, cached tokens, delegated permissions, or agent-to-agent trust boundaries.

| | |
|---|---|
| **Tollgate Coverage** | Strong |
| **Features** | HMAC-SHA256 agent identity signing (`sign_agent_context`), `verify_fn` on ControlTower rejects unsigned/tampered contexts, multi-agent delegation tracking (`delegated_by` chain), `max_delegation_depth`, `allowed_delegators` / `blocked_delegators` policy rules |

---

### ASI04 — Agentic Supply Chain Vulnerabilities

Compromised tools, descriptors, models, or personas influencing agent behavior. Dynamic MCP ecosystems revealed how easily runtime components can be poisoned.

| | |
|---|---|
| **Tollgate Coverage** | Strong |
| **Features** | HMAC-SHA256 manifest signing (`sign_manifest`/`verify_manifest`), `ToolRegistry` with `signing_key` rejects tampered manifests at startup, developer-controlled tool metadata (agent claims are untrusted), content hash for audit trail (`get_manifest_hash`) |

---

### ASI05 — Unexpected Code Execution

Agents generating or executing untrusted or attacker-controlled code. If an agent can write, evaluate, or execute code, an attacker can inject malicious logic via natural language.

| | |
|---|---|
| **Tollgate Coverage** | Moderate |
| **Features** | Effect-based gating (code execution tools marked as WRITE/DELETE get policy checks), parameter validation prevents injection in tool arguments, `NetworkGuard` blocks exfiltration endpoints |
| **Gaps** | Tollgate does not sandbox code execution itself; it gates access to code-execution tools |

---

### ASI06 — Memory & Context Poisoning

Persistent corruption of agent memory, RAG stores, embeddings, or contextual knowledge. Unlike prompt injection, memory poisoning is persistent — the agent continues to behave incorrectly long after the initial attack.

| | |
|---|---|
| **Tollgate Coverage** | Strong |
| **Features** | `ContextIntegrityMonitor` with SHA-256 snapshots detects tampering of immutable fields (system prompt, permissions, security level), configurable immutable field sets, alert callbacks for real-time notification of violations |

---

### ASI07 — Insecure Inter-Agent Communication

Weak agent-to-agent communication allows attackers to spoof or intercept messages. If channels aren't authenticated, encrypted, or validated, attackers can impersonate trusted agents.

| | |
|---|---|
| **Tollgate Coverage** | Moderate |
| **Features** | `delegated_by` chain tracks delegation provenance, `allowed_delegators` / `blocked_delegators` enforce trust boundaries, HMAC-signed agent contexts prevent impersonation |
| **Gaps** | Tollgate does not handle transport-layer encryption between agents; it enforces identity and authorization at the tool-call boundary |

---

### ASI08 — Cascading Failures

Small inaccuracies compound across chained agent decisions and actions. What begins as a minor misalignment can trigger system-wide outages or operational loops.

| | |
|---|---|
| **Tollgate Coverage** | Strong |
| **Features** | `InMemoryCircuitBreaker` with CLOSED → OPEN → HALF_OPEN state machine auto-disables failing tools, `InMemoryRateLimiter` with sliding window prevents runaway loops, per-agent and per-tool rate limits, anomaly detection (`AnomalyDetector`) alerts on error bursts and rate spikes |

---

### ASI09 — Human-Agent Trust Exploitation

Humans overly relying on agent recommendations, leading to unsafe approvals. Confident, polished explanations can mislead operators into approving harmful actions.

| | |
|---|---|
| **Tollgate Coverage** | Moderate |
| **Features** | `ASK` policy decision forces human-in-the-loop for sensitive operations, `CliApprover` shows full context (agent, intent, tool, params) before approval, `request_hash` binding prevents TOCTOU attacks on approval, `AsyncQueueApprover` with timeout and default-DENY |
| **Gaps** | Tollgate surfaces the decision to humans but cannot prevent cognitive biases in human reviewers |

---

### ASI10 — Rogue Agents

Misaligned or compromised agents that diverge from intended behavior while appearing legitimate. They may self-repeat actions, persist across sessions, or impersonate other agents.

| | |
|---|---|
| **Tollgate Coverage** | Strong |
| **Features** | Agent identity verification prevents impersonation, rate limiting detects repetitive behavior, `AnomalyDetector` flags unusual tool usage patterns, delegation chain tracking identifies unauthorized sub-agents, circuit breaker halts failing tools, structured audit trail for forensic analysis |

---

### Coverage Summary

| Risk | ID | Tollgate Coverage | Key Features |
|------|-----|-------------------|-------------|
| Agent Goal Hijack | ASI01 | Partial | Policy rules, delegation controls, context integrity |
| Tool Misuse | ASI02 | **Strong** | Parameter validation, URL constraints, NetworkGuard |
| Identity & Privilege Abuse | ASI03 | **Strong** | Agent signing, delegation tracking |
| Supply Chain Vulnerabilities | ASI04 | **Strong** | Manifest signing, trusted registry |
| Unexpected Code Execution | ASI05 | Moderate | Effect gating, parameter validation |
| Memory & Context Poisoning | ASI06 | **Strong** | Context integrity monitor |
| Insecure Inter-Agent Comms | ASI07 | Moderate | Delegation provenance, signed contexts |
| Cascading Failures | ASI08 | **Strong** | Circuit breaker, rate limiting, anomaly detection |
| Human-Agent Trust Exploitation | ASI09 | Moderate | Human-in-the-loop, approval integrity |
| Rogue Agents | ASI10 | **Strong** | Identity verification, anomaly detection, audit |

> **Reference**: [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## Security Best Practices

### 1. Sign Everything
- Sign manifests at build time
- Sign agent contexts before use
- Verify signatures at runtime

### 2. Deny by Default
- Use `default="deny"` for NetworkGuard
- Ensure policy has a final catch-all DENY rule
- Don't allow unknown effects

### 3. Limit Scope
- Use rate limits for all agents
- Set `max_delegation_depth` in policies
- Define URL constraints per tool

### 4. Monitor Everything
- Enable `JsonlAuditSink` for compliance
- Use `WebhookAuditSink` for real-time alerts
- Deploy `AnomalyDetector` for pattern detection

### 5. Use Persistent Backends in Production
- Use `SQLiteGrantStore` for single-process deployments
- Use `RedisGrantStore` for distributed deployments
- Don't use in-memory stores in production

### 6. Test Policies in CI
- Define policy test scenarios
- Run `tollgate test-policy` in CI pipelines
- Fail builds on policy regressions

## Reporting a Vulnerability

Please report security vulnerabilities directly to the maintainers via GitHub Issues (marked as private if possible) or as instructed in the repository metadata.

## Audit Logs

Ensure your `AuditSink` is configured to store logs securely. Tollgate emits structured JSONL logs that include:
- `schema_version`: For forward compatibility
- `correlation_id`: For request tracing
- `request_hash`: For integrity verification
- `outcome`: ALLOWED, BLOCKED, FAILED, etc.
- `grant_id`: When grants are used

Treat these logs as sensitive as they may contain proprietary tool arguments.

## Security Checklist

- [ ] Manifests are signed at build time
- [ ] Agent contexts are signed before use
- [ ] `verify_fn` is configured on `ControlTower`
- [ ] Rate limits are configured for all effects
- [ ] Circuit breaker is enabled
- [ ] NetworkGuard is configured with `default="deny"`
- [ ] Audit sink is configured and logs are secured
- [ ] Policy test scenarios exist and run in CI
- [ ] Delegation depth limits are enforced
- [ ] Anomaly detection is enabled for production
