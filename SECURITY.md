# Security Policy

## Supported Versions

Only the latest version of `tollgate` is supported for security updates.

## Reporting a Vulnerability

Please report security vulnerabilities directly to the maintainers via GitHub Issues (marked as private if possible) or as instructed in the repo metadata.

## Deterministic Policies

`tollgate` is designed for **deterministic** enforcement. We strongly advise against using LLMs to make policy decisions within the tollgate layer, as this introduces non-determinism and potential jailbreak vectors.

## Audit Logs

Ensure your `AuditSink` is configured to store logs securely. `tollgate` emits structured JSONL logs that should be treated as sensitive if they contain PII or proprietary tool arguments.
