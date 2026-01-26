import hashlib
from pathlib import Path
from typing import Any, Protocol

import yaml

from .types import AgentContext, Decision, DecisionType, Effect, Intent, ToolRequest


class PolicyEvaluator(Protocol):
    """Protocol for policy evaluation."""

    def evaluate(
        self, agent_ctx: AgentContext, intent: Intent, tool_request: ToolRequest
    ) -> Decision:
        """Evaluate a tool request against the policy."""
        ...


class YamlPolicyEvaluator:
    """YAML-based policy evaluator with safe defaults."""

    def __init__(
        self,
        policy_path: str | Path,
        default_if_unknown: DecisionType = DecisionType.DENY,
    ):
        """Load and validate policy from YAML file."""
        self.path = Path(policy_path)
        with self.path.open("r") as f:
            content = f.read()
            self.data = yaml.safe_load(content)
            self.version = self.data.get(
                "version", hashlib.sha256(content.encode()).hexdigest()[:8]
            )

        self.rules = self.data.get("rules", [])
        self.default_if_unknown = default_if_unknown
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
        # Principle 2: Safe Defaults for unknown effect/resource
        if tool_request.effect == Effect.UNKNOWN:
            return Decision(
                decision=self.default_if_unknown,
                reason="Unknown tool effect. Safe default applied.",
                policy_version=self.version,
            )

        for rule in self.rules:
            if self._matches(rule, agent_ctx, intent, tool_request):
                # Principle 3: Trusted Attributes
                # If ALLOW, ensure effect and resource_type are from registry (trusted)
                decision = DecisionType(rule["decision"])
                if decision == DecisionType.ALLOW and not tool_request.manifest_version:
                    return Decision(
                        decision=DecisionType.ASK,
                        reason=(
                            "ALLOW decision requires trusted tool metadata "
                            "from registry."
                        ),
                        policy_version=self.version,
                    )

                return Decision(
                    decision=decision,
                    reason=rule.get("reason", "Rule matched"),
                    policy_id=rule.get("id"),
                    policy_version=self.version,
                    metadata=rule.get("metadata", {}),
                )

        return Decision(
            decision=DecisionType.DENY,
            reason="No matching policy rule found. Defaulting to DENY.",
            policy_version=self.version,
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

        # Match metadata conditions (Untrusted)
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
