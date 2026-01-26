import asyncio

from tollgate import (
    AgentContext,
    ControlTower,
    Intent,
    TollgateError,
)
from tollgate.interceptors.langchain import guard_tools
from tollgate.registry import ToolRegistry

from .tools import close_ticket, list_stale_tickets


class MockTool:
    """A minimal mock of a LangChain tool."""

    def __init__(self, name, func):
        self.name = name
        self.func = func
        self.description = f"Mock tool for {name}"

    def run(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], dict) and not kwargs:
            return self.func(**args[0])
        return self.func(*args, **kwargs)

    async def arun(self, *args, **kwargs):
        func_to_call = self.func
        if len(args) == 1 and isinstance(args[0], dict) and not kwargs:
            args_to_pass = []
            kwargs_to_pass = args[0]
        else:
            args_to_pass = args
            kwargs_to_pass = kwargs

        if asyncio.iscoroutinefunction(func_to_call):
            return await func_to_call(*args_to_pass, **kwargs_to_pass)
        return func_to_call(*args_to_pass, **kwargs_to_pass)


class TicketCleanupAgent:
    def __init__(self, tower: ControlTower, registry: ToolRegistry):
        self.tower = tower
        self.registry = registry
        self.ctx = AgentContext(
            agent_id="cleanup-bot", version="1.0.0", owner="ops-team"
        )

        # Principle 1: Interception-based gating
        raw_tools = [
            MockTool("list_stale_tickets", list_stale_tickets),
            MockTool("close_ticket", close_ticket),
        ]
        self.guarded_tools = guard_tools(raw_tools, tower, registry)

    async def run(self):
        intent = Intent(
            action="cleanup_stale_tickets", reason="Reducing backlog of old tickets"
        )

        print("\n--- Agent: Searching for stale tickets ---")
        list_tool = next(
            t for t in self.guarded_tools if t.name == "list_stale_tickets"
        )
        stale_tickets = await list_tool.ainvoke(
            {"min_age_days": 90}, agent_ctx=self.ctx, intent=intent
        )
        print(f"Found {len(stale_tickets)} stale tickets.")

        close_tool = next(t for t in self.guarded_tools if t.name == "close_ticket")
        for ticket in stale_tickets:
            print(
                f"\n--- Agent: Attempting to close {ticket['id']} "
                f"(Age: {ticket['age_days']} days, VIP: {ticket['is_vip']}) ---"
            )

            # Look up ticket details to provide TRUSTED metadata for the closure
            trusted_metadata = {
                "ticket_age_days": ticket["age_days"],
                "is_vip": ticket["is_vip"],
            }

            try:
                result = await close_tool.ainvoke(
                    {"ticket_id": ticket["id"]},
                    agent_ctx=self.ctx,
                    intent=intent,
                    metadata=trusted_metadata,
                )
                print(f"Success: {result['message']}")
            except TollgateError as e:
                print(f"Blocked by Tollgate: {e}")
