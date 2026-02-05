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

## OWASP Agentic Application Security Coverage

Tollgate addresses the following risks from the OWASP Top 10 for Agentic Applications:

| Risk | Coverage | Features |
|------|----------|----------|
| Agent Goal Hijack | Partial | Policy rules, delegation controls |
| Tool Misuse | Strong | Parameter validation, URL constraints, NetworkGuard |
| Identity Abuse | Strong | Agent signing, delegation tracking |
| Cascading Failures | Strong | Circuit breaker, rate limiting |
| Data Exfiltration | Strong | READ gating, NetworkGuard, URL constraints |
| Supply Chain | Strong | Manifest signing, trusted registry |
| Excessive Agency | Moderate | Rate limiting, policy rules |
| Audit Gaps | Strong | Structured audit, anomaly detection |

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
