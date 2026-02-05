#!/usr/bin/env python3
"""Security Hardened Tollgate Demo

Demonstrates all security features:
- Agent identity signing
- Rate limiting
- Circuit breaker
- NetworkGuard
- Parameter validation
- Delegation controls
- Anomaly detection
- Context integrity monitoring
- Policy testing

Run: python examples/security_hardened/demo.py
"""

import asyncio
import time
from pathlib import Path

# Tollgate imports
from tollgate import (
    # Core
    ControlTower, AgentContext, Intent, ToolRequest, Effect,
    # Policy & Registry
    YamlPolicyEvaluator, ToolRegistry,
    # Security layers
    InMemoryRateLimiter, InMemoryCircuitBreaker, NetworkGuard,
    sign_agent_context, make_verifier, sign_manifest,
    # Grants
    InMemoryGrantStore, Grant,
    # Audit
    JsonlAuditSink, CompositeAuditSink, AnomalyDetector,
    # Monitoring
    ContextIntegrityMonitor,
    # Testing
    PolicyTestRunner,
    # Approvals
    AutoApprover,
    # Exceptions
    TollgateRateLimited, TollgateDenied,
)

# File paths
EXAMPLE_DIR = Path(__file__).parent
MANIFEST_PATH = EXAMPLE_DIR / "manifest.yaml"
POLICY_PATH = EXAMPLE_DIR / "policy.yaml"
SCENARIOS_PATH = EXAMPLE_DIR / "test_scenarios.yaml"
AUDIT_PATH = EXAMPLE_DIR / "audit.jsonl"

# Secrets (in production, use environment variables or secret management)
MANIFEST_SECRET = b"manifest-signing-key-12345"
AGENT_SECRET = b"agent-signing-key-67890"


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


async def demo_policy_testing():
    """Demo: Policy Testing Framework"""
    print_section("Policy Testing Framework")

    runner = PolicyTestRunner(str(POLICY_PATH), str(SCENARIOS_PATH))
    results = runner.run()

    print(results.summary())

    if results.all_passed:
        print("All policy tests passed!")
    else:
        print("WARNING: Some policy tests failed!")

    return results.all_passed


async def demo_full_security_stack():
    """Demo: Full Security Stack"""
    print_section("Full Security Stack Demo")

    # 1. Sign the manifest (normally done at build time)
    print("\n1. Signing manifest...")
    sign_manifest(str(MANIFEST_PATH), secret_key=MANIFEST_SECRET)
    print("   Manifest signed successfully")

    # 2. Initialize all security layers
    print("\n2. Initializing security layers...")

    # Tool registry with signature verification
    registry = ToolRegistry(str(MANIFEST_PATH), signing_key=MANIFEST_SECRET)
    print("   - ToolRegistry (with signature verification)")

    # Policy evaluator
    policy = YamlPolicyEvaluator(str(POLICY_PATH))
    print("   - YamlPolicyEvaluator")

    # Rate limiter
    rate_limiter = InMemoryRateLimiter([
        {"agent_id": "*", "tool": "*", "max_calls": 10, "window_seconds": 60},
        {"agent_id": "*", "effect": "write", "max_calls": 3, "window_seconds": 60},
    ])
    print("   - RateLimiter (10 calls/min global, 3 writes/min)")

    # Circuit breaker
    circuit_breaker = InMemoryCircuitBreaker(
        failure_threshold=3,
        cooldown_seconds=30,
    )
    print("   - CircuitBreaker (threshold=3, cooldown=30s)")

    # Network guard
    network_guard = NetworkGuard(
        default="deny",
        allowlist=[
            {"pattern": "https://api.github.com/*"},
            {"pattern": "https://api.example.com/*"},
        ],
        blocklist=[
            {"pattern": "http://*"},
        ],
    )
    print("   - NetworkGuard (default=deny, HTTPS only)")

    # Anomaly detector
    alerts_received = []
    anomaly_detector = AnomalyDetector(
        window_seconds=60,
        z_score_threshold=2.0,
        min_samples=3,
        alert_callback=lambda alert: alerts_received.append(alert),
    )
    print("   - AnomalyDetector (z-score threshold=2.0)")

    # Audit sink
    file_sink = JsonlAuditSink(str(AUDIT_PATH))
    composite_audit = CompositeAuditSink([file_sink, anomaly_detector])
    print("   - CompositeAuditSink (JSONL + anomaly detection)")

    # Grant store
    grant_store = InMemoryGrantStore()
    print("   - InMemoryGrantStore")

    # Context integrity monitor
    context_monitor = ContextIntegrityMonitor(
        immutable_fields={"system_prompt", "security_level"},
    )
    print("   - ContextIntegrityMonitor")

    # Create the ControlTower
    tower = ControlTower(
        policy=policy,
        approver=AutoApprover(),
        audit=composite_audit,
        registry=registry,
        grant_store=grant_store,
        rate_limiter=rate_limiter,
        circuit_breaker=circuit_breaker,
        network_guard=network_guard,
        verify_fn=make_verifier(AGENT_SECRET),
    )
    print("   - ControlTower (all layers connected)")

    # 3. Create and sign agent context
    print("\n3. Creating signed agent context...")
    agent = sign_agent_context(
        AgentContext(
            agent_id="demo-agent",
            version="1.0.0",
            owner="demo-team",
        ),
        AGENT_SECRET,
    )
    print(f"   Agent: {agent.agent_id} (signed)")

    # Take context snapshot for integrity monitoring
    agent_context_data = {
        "system_prompt": "You are a helpful assistant",
        "security_level": "standard",
        "session_data": {"counter": 0},
    }
    context_monitor.snapshot(agent.agent_id, "turn-1", agent_context_data)
    print("   Context snapshot taken")

    # 4. Demo: Successful read operation
    print("\n4. Executing READ operation...")
    intent = Intent(action="fetch_data", reason="Demo: fetch data")
    request = ToolRequest(
        tool="api:fetch_data",
        action="get",
        resource_type="data",
        effect=Effect.READ,
        params={"url": "https://api.github.com/users"},
        manifest_version="1.0.0",
    )

    async def fetch_data():
        return {"data": "example response"}

    try:
        result = await tower.execute_async(
            agent, intent, request,
            fetch_data,
        )
        print(f"   SUCCESS: {result}")
    except Exception as e:
        print(f"   FAILED: {e}")

    # 5. Demo: Delegation chain
    print("\n5. Testing delegation chain...")
    delegated_agent = sign_agent_context(
        AgentContext(
            agent_id="worker-agent",
            version="1.0.0",
            owner="demo-team",
            delegated_by=("orchestrator",),  # Trusted delegator
        ),
        AGENT_SECRET,
    )
    print(f"   Delegated agent: {delegated_agent.agent_id}")
    print(f"   Delegation depth: {delegated_agent.delegation_depth}")
    print(f"   Root agent: {delegated_agent.root_agent}")

    write_request = ToolRequest(
        tool="api:write_file",
        action="put",
        resource_type="file",
        effect=Effect.WRITE,
        params={"path": "/safe/test.txt", "content": "Hello"},
        manifest_version="1.0.0",
    )
    write_intent = Intent(action="write_file", reason="Demo: write file")

    async def write_file():
        return {"status": "written"}

    try:
        result = await tower.execute_async(
            delegated_agent, write_intent, write_request,
            write_file,
        )
        print(f"   SUCCESS (trusted delegation): {result}")
    except Exception as e:
        print(f"   RESULT: {e}")

    # 6. Demo: Deep delegation blocked
    print("\n6. Testing deep delegation chain (should be blocked)...")
    deep_agent = sign_agent_context(
        AgentContext(
            agent_id="deep-worker",
            version="1.0.0",
            owner="demo-team",
            delegated_by=("a", "b", "c"),  # Depth 3
        ),
        AGENT_SECRET,
    )
    print(f"   Delegation depth: {deep_agent.delegation_depth}")

    try:
        result = await tower.execute_async(
            deep_agent, write_intent, write_request,
            write_file,
        )
        print(f"   UNEXPECTED SUCCESS: {result}")
    except TollgateDenied as e:
        print(f"   BLOCKED (as expected): {e}")

    # 7. Demo: Context integrity check
    print("\n7. Verifying context integrity...")

    # Verify unchanged context
    result = context_monitor.verify(agent.agent_id, "turn-1", agent_context_data)
    print(f"   Unchanged context: {'VALID' if result.is_valid else 'INVALID'}")

    # Simulate tampering
    tampered_context = dict(agent_context_data)
    tampered_context["security_level"] = "admin"  # Tampered!

    result = context_monitor.verify(agent.agent_id, "turn-1", tampered_context)
    print(f"   Tampered context: {'VALID' if result.is_valid else 'INVALID'}")
    if not result.is_valid:
        print(f"   Changed fields: {result.changed_fields}")

    # 8. Demo: Rate limiting
    print("\n8. Testing rate limiting...")
    for i in range(12):
        async def make_response():
            return {"data": f"response {i}"}

        try:
            await tower.execute_async(
                agent, intent, request,
                make_response,
            )
            print(f"   Call {i+1}: SUCCESS")
        except TollgateRateLimited as e:
            print(f"   Call {i+1}: RATE LIMITED")
            break
        except TollgateDenied as e:
            print(f"   Call {i+1}: DENIED - {e}")
            break

    # 9. Stats summary
    print("\n9. Security stats...")
    print(f"   Anomaly alerts: {len(alerts_received)}")
    for alert in alerts_received:
        print(f"     - {alert.alert_type}: {alert.message}")

    detector_stats = anomaly_detector.get_stats()
    print(f"   Agents tracked: {detector_stats['agents_tracked']}")

    print("\n" + "="*60)
    print("  Demo Complete!")
    print("="*60)


async def main():
    """Run all demos."""
    print("\n" + "="*60)
    print("  TOLLGATE SECURITY HARDENED DEMO")
    print("  Demonstrating All Security Features")
    print("="*60)

    # Run policy tests first
    tests_passed = await demo_policy_testing()

    # Run full security stack demo
    await demo_full_security_stack()

    if tests_passed:
        print("\n All demos completed successfully!")
    else:
        print("\n Demo completed with warnings (some policy tests failed)")


if __name__ == "__main__":
    asyncio.run(main())
