import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from .approvals import Approver, compute_request_hash
from .audit import AuditSink
from .exceptions import (
    TollgateApprovalDenied,
    TollgateDeferred,
    TollgateDenied,
)
from .grants import GrantStore
from .policy import PolicyEvaluator
from .types import (
    AgentContext,
    ApprovalOutcome,
    AuditEvent,
    Decision,
    DecisionType,
    Intent,
    Outcome,
    ToolRequest,
)


class ControlTower:
    """Async-first control tower for tool execution enforcement."""

    def __init__(
        self,
        policy: PolicyEvaluator,
        approver: Approver,
        audit: AuditSink,
        grant_store: GrantStore | None = None,
        redact_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ):
        self.policy = policy
        self.approver = approver
        self.audit = audit
        self.grant_store = grant_store
        self.redact_fn = redact_fn or self._default_redact

    @staticmethod
    def _default_redact(params: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive keys by default."""
        sensitive_keys = {
            "password",
            "token",
            "secret",
            "authorization",
            "api_key",
            "key",
        }
        return {
            k: ("[REDACTED]" if k.lower() in sensitive_keys else v)
            for k, v in params.items()
        }

    async def execute_async(
        self,
        agent_ctx: AgentContext,
        intent: Intent,
        tool_request: ToolRequest,
        exec_async: Callable[[], Awaitable[Any]],
    ) -> Any:
        """
        Evaluate and execute a tool call asynchronously.
        """
        correlation_id = str(uuid.uuid4())
        request_hash = compute_request_hash(agent_ctx, intent, tool_request)

        # 1. Evaluate Policy
        decision = self.policy.evaluate(agent_ctx, intent, tool_request)

        # 2. Handle DENY
        if decision.decision == DecisionType.DENY:
            self._log(
                correlation_id,
                request_hash,
                agent_ctx,
                intent,
                tool_request,
                decision,
                Outcome.BLOCKED,
            )
            raise TollgateDenied(decision.reason)

        # 3. Handle ASK
        if decision.decision == DecisionType.ASK:
            # 3.1 Check Grants
            if self.grant_store:
                matching_grant = await self.grant_store.find_matching_grant(
                    agent_ctx, tool_request
                )
                if matching_grant:
                    # Grant found! Proceed to execution without asking approver
                    result = await self._execute_and_log(
                        correlation_id,
                        request_hash,
                        agent_ctx,
                        intent,
                        tool_request,
                        decision,
                        exec_async,
                        grant_id=matching_grant.id,
                    )
                    return result

            # 3.2 Request Approval if no grant found
            outcome = await self.approver.request_approval_async(
                agent_ctx, intent, tool_request, request_hash, decision.reason
            )

            if outcome == ApprovalOutcome.DEFERRED:
                # Audit the deferral
                self._log(
                    correlation_id,
                    request_hash,
                    agent_ctx,
                    intent,
                    tool_request,
                    decision,
                    Outcome.BLOCKED,  # Deferral is a temporary block
                )
                raise TollgateDeferred("pending")

            if outcome != ApprovalOutcome.APPROVED:
                final_outcome = (
                    Outcome.TIMEOUT
                    if outcome == ApprovalOutcome.TIMEOUT
                    else Outcome.APPROVAL_DENIED
                )
                self._log(
                    correlation_id,
                    request_hash,
                    agent_ctx,
                    intent,
                    tool_request,
                    decision,
                    final_outcome,
                )
                raise TollgateApprovalDenied(f"Approval failed: {outcome.value}")

        # 4. Execute tool (Policy ALLOW or Approval APPROVED)
        return await self._execute_and_log(
            correlation_id,
            request_hash,
            agent_ctx,
            intent,
            tool_request,
            decision,
            exec_async,
        )

    async def _execute_and_log(
        self,
        correlation_id: str,
        request_hash: str,
        agent_ctx: AgentContext,
        intent: Intent,
        tool_request: ToolRequest,
        decision: Decision,
        exec_async: Callable[[], Awaitable[Any]],
        grant_id: str | None = None,
    ) -> Any:
        """Internal helper to execute tool and log result."""
        result = None
        outcome = Outcome.EXECUTED
        try:
            result = await exec_async()
        except Exception as e:
            outcome = Outcome.FAILED
            result_summary = self._sanitize_exception(e)
            self._log(
                correlation_id,
                request_hash,
                agent_ctx,
                intent,
                tool_request,
                decision,
                outcome,
                grant_id=grant_id,
                result_summary=result_summary,
            )
            raise

        # Final Audit
        result_summary = self._truncate_result(result)
        self._log(
            correlation_id,
            request_hash,
            agent_ctx,
            intent,
            tool_request,
            decision,
            outcome,
            grant_id=grant_id,
            result_summary=result_summary,
        )

        return result

    def execute(
        self,
        agent_ctx: AgentContext,
        intent: Intent,
        tool_request: ToolRequest,
        exec_sync: Callable[[], Any],
    ) -> Any:
        """Sync wrapper for execute_async. Safe only if no event loop is running."""
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                raise RuntimeError(
                    "execute() called from within a running event loop. "
                    "Use execute_async() instead."
                )
        except RuntimeError:
            pass

        async def _exec():
            return exec_sync()

        return asyncio.run(
            self.execute_async(agent_ctx, intent, tool_request, _exec)
        )

    def _log(
        self,
        correlation_id: str,
        request_hash: str,
        agent: AgentContext,
        intent: Intent,
        req: ToolRequest,
        decision: Decision,
        outcome: Outcome,
        approval_id: str | None = None,
        grant_id: str | None = None,
        result_summary: str | None = None,
    ):
        # Redact params before logging
        redacted_req = ToolRequest(
            tool=req.tool,
            action=req.action,
            resource_type=req.resource_type,
            effect=req.effect,
            params=self.redact_fn(req.params),
            metadata=req.metadata,
            manifest_version=req.manifest_version,
        )

        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            correlation_id=correlation_id,
            request_hash=request_hash,
            agent=agent,
            intent=intent,
            tool_request=redacted_req,
            decision=decision,
            outcome=outcome,
            approval_id=approval_id,
            grant_id=grant_id,
            result_summary=result_summary,
            policy_version=decision.policy_version,
            manifest_version=req.manifest_version,
        )
        self.audit.emit(event)

    def _sanitize_exception(self, e: Exception) -> str:
        """Sanitize exception message to avoid leaking sensitive data."""
        # Only include the exception type and a generic message for security
        return f"{type(e).__name__}: Execution failed"

    def _truncate_result(self, result: Any, max_chars: int = 200) -> str | None:
        if result is None:
            return None
        s = str(result)
        return s[:max_chars] + "..." if len(s) > max_chars else s
