from pathlib import Path
from typing import Any, Protocol

import yaml

from .types import AgentContext, Decision, DecisionType, Intent, ToolRequest


class PolicyEvaluator(Protocol):
    """Protocol for policy evaluation."""

    def evaluate(
        self, agent_ctx: AgentContext, intent: Intent, tool_request: ToolRequest
    ) -> Decision:
        """Evaluate a tool request against the policy."""
        ...


class YamlPolicyEvaluator:
    """YAML-based policy evaluator."""

    def __init__(self, policy_path: str | Path):
        """Load and validate policy from YAML file."""
        with Path(policy_path).open() as f:
            self.data = yaml.safe_load(f)
        self.rules = self.data.get("rules", [])
        self._validate_rules()

    def _validate_rules(self):
        """Basic validation of rule structure."""
        for i, rule in enumerate(self.rules):
            if "decision" not in rule:
                raise ValueError(f"Rule at index {i} is missing 'decision' key")
            try:
                DecisionType(rule["decision"])
            except ValueError:
                raise ValueError(
                    f"Invalid decision '{rule['decision']}' in rule at index {i}"
                ) from None

    def evaluate(
        self, agent_ctx: AgentContext, intent: Intent, tool_request: ToolRequest
    ) -> Decision:
        """Evaluate a tool request against loaded rules."""
        for rule in self.rules:
            if self._matches(rule, agent_ctx, intent, tool_request):
                return Decision(
                    decision=DecisionType(rule["decision"]),
                    reason=rule.get("reason", "Rule matched"),
                    policy_id=rule.get("id"),
                    metadata=rule.get("metadata", {}),
                )

        return Decision(
            decision=DecisionType.DENY,
            reason="No matching policy rule found. Defaulting to DENY.",
        )

    def _matches(
        self,
        rule: dict,
        agent_ctx: AgentContext,
        intent: Intent,
        req: ToolRequest,
    ) -> bool:
        # Match tool, action, resource_type, effect
        if "tool" in rule and rule["tool"] != req.tool:
            return False
        if "action" in rule and rule["action"] != req.action:
            return False
        if "resource_type" in rule and rule["resource_type"] != req.resource_type:
            return False
        if "effect" in rule and rule["effect"] != req.effect.value:
            return False

        # Match Agent Context
        if "agent" in rule:
            for key, expected_val in rule["agent"].items():
                if getattr(agent_ctx, key, None) != expected_val:
                    return False

        # Match Intent
        if "intent" in rule:
            for key, expected_val in rule["intent"].items():
                if getattr(intent, key, None) != expected_val:
                    return False

        # Match tool_request.metadata conditions
        if "when" in rule:
            for key, condition in rule["when"].items():
                val = req.metadata.get(key)
                if not self._check_condition(val, condition):
                    return False

        return True

    def _check_condition(self, val: Any, condition: Any) -> bool:
        """Check a single condition against a value."""
        if isinstance(condition, dict):
            for op, target in condition.items():
                # Null check to prevent TypeError on comparisons
                if val is None and op in (">", ">=", "<", "<="):
                    return False

                if op == "==" and val != target:
                    return False
                if op == "!=" and val == target:
                    return False
                if op == ">" and not (val > target):
                    return False
                if op == ">=" and not (val >= target):
                    return False
                if op == "<" and not (val < target):
                    return False
                if op == "<=" and not (val <= target):
                    return False
            return True
        return val == condition
