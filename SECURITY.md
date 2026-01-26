# Security Policy

## Supported Versions

Only the latest version of `tollgate` is supported for security updates.

## Core Security Guarantees (v1)

### 1. Trusted Tool Registry
`tollgate` enforces that tool metadata (`effect`, `resource_type`) must originate from a developer-controlled **Tool Registry**. Agent-provided claims about a tool's impact are treated as untrusted.

### 2. Deterministic Enforcement
All policy decisions are deterministic. We strongly advise against using non-deterministic models (LLMs) to make final gating decisions, as this introduces potential jailbreak vectors.

### 3. Approval Integrity
Approval requests are cryptographically bound to a `request_hash` (fingerprint of the agent, intent, tool, parameters, and trusted metadata). If the request is modified or the policy changes during a pending approval, the hash will mismatch, requiring re-evaluation.

### 4. Safe Defaults
By default, any tool with an unknown effect or resource type will be subject to a `DENY` or `ASK` decision (configurable). No heuristic inference will ever result in an `ALLOW` by default.

## Reporting a Vulnerability

Please report security vulnerabilities directly to the maintainers via GitHub Issues (marked as private if possible) or as instructed in the repository metadata.

## Audit Logs

Ensure your `AuditSink` is configured to store logs securely. `tollgate` emits structured JSONL logs that include integrity hashes and correlation IDs. Treat these logs as sensitive as they may contain proprietary tool arguments.


