import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .approval import Approver
from .audit import AuditSink
from .exceptions import TollgateApprovalDenied, TollgateDenied
from .policy import PolicyEvaluator
from .types import (
    AgentContext,
    AuditEvent,
    Decision,
    DecisionType,
    Intent,
    Outcome,
    ToolRequest,
)


class ControlTower:
    def __init__(self, policy: PolicyEvaluator, approver: Approver, audit: AuditSink):
        self.policy = policy
        self.approver = approver
        self.audit = audit

    def execute(
        self,
        agent_ctx: AgentContext,
        intent: Intent,
        tool_request: ToolRequest,
        tool_callable: Callable | None = None,
    ) -> Any:
        """
        Evaluate and execute a tool call.

        1. Generate correlation ID.
        2. Evaluate policy.
        3. Request approval if policy returns ASK.
        4. Execute tool_callable if allowed.
        5. Audit result.
        """
        correlation_id = str(uuid.uuid4())

        # 1. Evaluate Policy
        decision = self.policy.evaluate(agent_ctx, intent, tool_request)

        # 2. Handle DENY
        if decision.decision == DecisionType.DENY:
            self._log(
                correlation_id,
                agent_ctx,
                intent,
                tool_request,
                decision,
                Outcome.BLOCKED,
            )
            raise TollgateDenied(decision.reason)

        # 3. Handle ASK
        if decision.decision == DecisionType.ASK:
            approved = self.approver.request_approval(
                agent_ctx, intent, tool_request, decision.reason
            )
            if not approved:
                self._log(
                    correlation_id,
                    agent_ctx,
                    intent,
                    tool_request,
                    decision,
                    Outcome.APPROVAL_DENIED,
                )
                raise TollgateApprovalDenied()

        # 4. Execute tool
        result = None
        outcome = Outcome.EXECUTED
        error_summary = None
        if tool_callable:
            try:
                result = tool_callable(**tool_request.params)
            except Exception as e:
                outcome = Outcome.FAILED
                error_summary = f"{type(e).__name__}: {str(e)}"
                self._log(
                    correlation_id,
                    agent_ctx,
                    intent,
                    tool_request,
                    decision,
                    outcome,
                    error_summary,
                )
                raise

        # 5. Final Audit
        result_summary = self._truncate_result(result)
        self._log(
            correlation_id,
            agent_ctx,
            intent,
            tool_request,
            decision,
            outcome,
            result_summary,
        )

        return result

    def _truncate_result(self, result: Any, max_chars: int = 200) -> str | None:
        """Safe truncation of tool result for audit logging."""
        if result is None:
            return None

        s = str(result)
        if len(s) <= max_chars:
            return s
        return s[:max_chars] + "..."

    def _log(
        self,
        correlation_id: str,
        agent: AgentContext,
        intent: Intent,
        req: ToolRequest,
        decision: Decision,
        outcome: Outcome,
        result_summary: str | None = None,
    ):
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            correlation_id=correlation_id,
            agent=agent,
            intent=intent,
            tool_request=req,
            decision=decision,
            outcome=outcome,
            result_summary=result_summary,
        )
        self.audit.emit(event)
