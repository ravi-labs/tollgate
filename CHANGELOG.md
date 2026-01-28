# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
