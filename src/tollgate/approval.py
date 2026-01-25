from typing import Protocol

from .types import AgentContext, Intent, ToolRequest


class Approver(Protocol):
    """Protocol for requesting human approval."""

    def request_approval(
        self,
        agent_ctx: AgentContext,
        intent: Intent,
        tool_request: ToolRequest,
        reason: str,
    ) -> bool:
        """Request approval from a human."""
        ...


class CliApprover:
    """A command-line interface approver."""

    def __init__(self, show_emojis: bool = True):
        """Initialize the CLI approver."""
        self.show_emojis = show_emojis

    def request_approval(
        self,
        agent_ctx: AgentContext,
        intent: Intent,
        tool_request: ToolRequest,
        reason: str,
    ) -> bool:
        """Prompt the user for approval via the terminal."""
        prefix = "🚦 " if self.show_emojis else ""
        print("\n" + "=" * 40)
        print(f"{prefix}TOLLGATE APPROVAL REQUESTED")
        print("=" * 40)
        print(f"Reason: {reason}")
        print(f"Agent:  {agent_ctx.agent_id} (v{agent_ctx.version})")
        print(f"Intent: {intent.action} - {intent.reason}")
        print(f"Tool:   {tool_request.tool}.{tool_request.action}")
        print(f"Params: {tool_request.params}")
        print("-" * 40)
        choice = input("Approve this tool call? (y/N): ").strip().lower()
        return choice == "y"
