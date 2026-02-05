# Security Hardened Example

This example demonstrates all security features added in the Month 1-3 roadmap:

## Features Demonstrated

### Month 1: Foundation
- **Parameter Schema Validation**: JSON Schema validation for tool parameters
- **Rate Limiting**: Sliding window rate limits per agent/tool/effect
- **Agent Identity Signing**: HMAC-SHA256 verification of agent contexts
- **URL Constraints**: Per-tool URL allowlisting
- **Webhook Alerts**: Real-time alerts for denied events
- **Audit Schema Versioning**: Forward-compatible audit events

### Month 2: Perimeter
- **Circuit Breaker**: Auto-disable failing tools
- **Manifest Signing**: HMAC-SHA256 integrity verification
- **NetworkGuard**: Global URL policy enforcement

### Month 3: Defense in Depth
- **Multi-Agent Delegation**: Track and control delegation chains
- **Policy Testing**: Declarative scenario-based testing
- **Context Integrity Monitor**: Detect memory/context poisoning
- **Anomaly Detection**: Z-score based rate spike detection

## Files

- `demo.py` - Main demo script showing all security layers
- `manifest.yaml` - Tool definitions with parameter schemas
- `policy.yaml` - Policy rules with delegation controls
- `test_scenarios.yaml` - Policy test scenarios

## Running

```bash
# From the tollgate root directory
python examples/security_hardened/demo.py

# Run policy tests
tollgate test-policy examples/security_hardened/policy.yaml \
  --scenarios examples/security_hardened/test_scenarios.yaml
```

## Security Layers

```
Request Flow:
  Agent Context
       │
       ▼
  ┌─────────────────────────────────┐
  │  1. Identity Verification       │  ← HMAC signature check
  │  2. Rate Limiting               │  ← Sliding window check
  │  3. Circuit Breaker             │  ← CLOSED/OPEN/HALF_OPEN
  │  4. Policy Evaluation           │  ← YAML rules + delegation
  │  5. NetworkGuard                │  ← URL allowlist/blocklist
  │  6. Parameter Validation        │  ← JSON Schema
  │  7. Constraint Checking         │  ← Per-tool URL patterns
  └─────────────────────────────────┘
       │
       ▼
  Tool Execution
       │
       ▼
  ┌─────────────────────────────────┐
  │  8. Audit Logging               │  ← JSONL + Webhook
  │  9. Anomaly Detection           │  ← Z-score analysis
  │ 10. Context Integrity           │  ← SHA-256 snapshots
  └─────────────────────────────────┘
```
