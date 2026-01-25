from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Effect(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    NOTIFY = "notify"


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    ASK = "ASK"
    DENY = "DENY"


class Outcome(str, Enum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    APPROVAL_DENIED = "approval_denied"
    FAILED = "failed"


@dataclass
class AgentContext:
    agent_id: str
    version: str
    owner: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Intent:
    action: str
    reason: str
    confidence: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolRequest:
    tool: str
    action: str
    resource_type: str
    effect: Effect
    params: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["effect"] = self.effect.value
        return d


@dataclass
class Decision:
    decision: DecisionType
    reason: str
    policy_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d


@dataclass
class AuditEvent:
    timestamp: str
    correlation_id: str
    agent: AgentContext
    intent: Intent
    tool_request: ToolRequest
    decision: Decision
    outcome: Outcome
    result_summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "agent": self.agent.to_dict(),
            "intent": self.intent.to_dict(),
            "tool_request": self.tool_request.to_dict(),
            "decision": self.decision.to_dict(),
            "outcome": self.outcome.value,
            "result_summary": self.result_summary,
        }
