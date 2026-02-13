# Tollgate Example Cases: Problems and Solutions

This page summarizes all showcase cases in a shareable format for leadership and stakeholder reviews.

## Run The Demos

```bash
# Fast before/after narrative (3-5 min)
.venv/bin/python examples/leadership_showcase/demo.py

# Full safety stack showcase (10-15 min)
.venv/bin/python examples/leadership_showcase/full_safety_showcase.py
```

## Case Summary

| # | Problem | How We Solve It | Demonstrated Outcome |
|---|---|---|---|
| 1 | Tool manifest can be tampered in supply chain | Manifest signing + verification at load time | Tampered manifest fails verification and registry loading |
| 2 | Agent identity can be spoofed | Signed `AgentContext` + `verify_fn` in `ControlTower` | Valid signed agent allowed; tampered identity denied |
| 3 | High-risk writes execute without oversight | Policy `ASK` + approval workflow + scoped grants | Write denied without grant, allowed with time-bound grant |
| 4 | Unknown tools/actions can run unexpectedly | Safe default `DENY` for unknown effect/tool metadata | Unknown tool call blocked before execution |
| 5 | Dangerous or malformed inputs reach tools | JSON schema parameter validation in registry | Invalid request blocked; valid request allowed |
| 6 | Agent can exfiltrate data to external endpoints | Global `NetworkGuard` + per-tool URL constraints | Exfiltration URL blocked; approved URL allowed |
| 7 | Agent loops can overload systems | Sliding-window rate limiting per agent/tool/effect | Calls over threshold are rate-limited |
| 8 | Repeated tool failures cause cascading incidents | Circuit breaker (`CLOSED -> OPEN -> HALF_OPEN`) | Failing tool auto-blocked until cooldown probe succeeds |
| 9 | Multi-agent delegation can bypass trust boundaries | Delegation-aware policy rules (allowed delegators, depth) | Trusted delegation allowed; untrusted/deep chains blocked |
| 10 | Session context can be poisoned between turns | Context integrity snapshots + immutable field checks | Tampering detected on immutable fields |
| 11 | Abnormal behavior patterns go unnoticed | Anomaly detection on audit stream | Unusual tool usage/rate anomalies detected |
| 12 | Audit logs can be altered after the fact | Immutable audit hash chain + signature verification | Tampering breaks chain verification |
| 13 | Audit logs may leak sensitive fields | Field-level encryption for audit payloads | Sensitive fields encrypted, decryptable only with key |
| 14 | Policy changes can introduce regressions | Scenario-based policy regression tests | Policy checks pass/fail before production rollout |
| 15 | Grants/approvals lost on restart | Persistent backend (SQLite/Redis) | Grants persist across service restarts |

## Why This Matters

- We stop unsafe actions **before execution**, not after incident response.
- We apply controls consistently across agent frameworks at runtime.
- We produce audit evidence suitable for governance, risk, and compliance reviews.
- We enable safer autonomy: limited where risky, fast where safe.
