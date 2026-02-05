# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-02-05 — "Defense in Depth"
### Added
- **Multi-Agent Delegation Security**: Extended `AgentContext` with `delegated_by` field to track delegation chains. New properties: `delegation_depth`, `is_delegated`, `root_agent`. Policy rules can now match on `max_delegation_depth`, `deny_delegated`, `allowed_delegators`, `blocked_delegators`.
- **Policy Testing Framework**: New `PolicyTestRunner` class for declarative scenario-based policy testing. Supports YAML test scenarios with expected decisions, reason matching, and policy ID verification. CI-friendly with `tollgate test-policy` CLI command.
- **Context Integrity Monitor**: New `ContextIntegrityMonitor` class to detect unauthorized modifications to agent context between turns. Uses SHA-256 checksums with configurable immutable fields.
- **Anomaly Detection**: New `AnomalyDetector` class implementing the `AuditSink` protocol. Detects rate spikes, error bursts, deny surges, and unusual tool usage using z-score analysis on sliding windows.

### Changed
- Policy evaluator now supports delegation-aware matching in `agent:` section
- `__all__` exports updated with all new components

## [1.3.0] - 2026-02-01 — "Extend the Perimeter"
### Added
- **Circuit Breaker Pattern**: New `InMemoryCircuitBreaker` with CLOSED → OPEN → HALF_OPEN state machine. Auto-disables failing tools after configurable threshold. Integrated into `ControlTower`.
- **Manifest Signing**: New `sign_manifest()`, `verify_manifest()`, and `get_manifest_hash()` functions for HMAC-SHA256 integrity verification. `ToolRegistry` supports `signing_key` parameter.
- **NetworkGuard**: Global URL policy enforcement with allowlist/blocklist patterns. Checks configurable parameter fields (`url`, `endpoint`, etc.). Supports `default="deny"` or `default="allow"`.
- **Persistent Backends**: New `tollgate.backends` package with SQLite and Redis stores.
  - `SQLiteGrantStore` / `SQLiteApprovalStore`: Zero-dependency persistent storage with WAL mode
  - `RedisGrantStore` / `RedisApprovalStore`: Distributed storage with automatic TTL and pub/sub notifications
- **Optional Redis Dependency**: Install with `pip install tollgate[redis]`

### Changed
- `ControlTower` constructor now accepts `circuit_breaker` and `network_guard` parameters
- All backends implement the existing `GrantStore` and `ApprovalStore` protocols

## [1.2.0] - 2026-01-30 — "Harden the Foundation"
### Added
- **Parameter Schema Validation**: `ToolRegistry` now validates tool parameters against JSON Schema defined in `manifest.yaml` under `params_schema`. Supports type, required, pattern, enum, min/max constraints.
- **Rate Limiting**: New `RateLimiter` protocol and `InMemoryRateLimiter` implementation. Supports per-agent, per-tool, per-effect sliding window limits. New `TollgateRateLimited` exception.
- **Agent Identity Signing**: New `sign_agent_context()`, `verify_agent_context()`, and `make_verifier()` functions for HMAC-SHA256 agent verification. Signature stored in `metadata["_signature"]`.
- **URL Constraints**: Per-tool `constraints` section in manifest with `allowed_url_patterns` and `blocked_url_patterns`.
- **Webhook Alerts**: New `WebhookAuditSink` that fires HTTP POST on BLOCKED/DENIED/FAILED outcomes.
- **Composite Audit Sink**: New `CompositeAuditSink` to chain multiple audit sinks.
- **Audit Schema Versioning**: `AuditEvent` now includes `schema_version` field (currently "1.0").

### Changed
- `ControlTower` constructor now accepts `rate_limiter` and `verify_fn` parameters
- Audit events include constraint violation details

## [1.1.0] - 2026-01-28
### Added
- **Session Grants**: Introduced `Grant` and `InMemoryGrantStore` to allow bypassing human approval for specific, pre-authorized actions.
- **Grant ID Auto-generation**: Grant IDs are now automatically generated if not provided.
- **Grant Usage Tracking**: Added usage counters to `InMemoryGrantStore`.
- **Audit Integration**: Audit events now include `grant_id` when a grant is used.
- **Security**: Re-added and enforced exception sanitization in audit logs.

## [1.0.0] - 2026-01-27
### Added
- **Interception-First Architecture**: Added `TollgateInterceptor` and framework adapters for LangChain and OpenAI.
- **Trusted Tool Registry**: Introduced `ToolRegistry` to enforce developer-controlled tool metadata.
- **Async-First Execution**: The `ControlTower` now natively supports asynchronous tool execution and approvals.
- **Approval Integrity**: Added `request_hash` binding and `ApprovalStore` for secure, persistent async approvals.
- **Safe Defaults**: Policies now enforce `DENY` for unknown effects and require trusted attributes for `ALLOW`.
- **Structured Audit v2**: Enhanced audit logs with `correlation_id`, `request_hash`, and manifest versions.

## [0.0.1] - 2026-01-25
### Added
- Initial v0 release of `tollgate`.
