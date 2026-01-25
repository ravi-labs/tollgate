from tollgate import (
    AgentContext,
    ControlTower,
    Effect,
    Intent,
    TollgateError,
    wrap_tool,
)

from .tools import close_ticket, list_stale_tickets


class TicketCleanupAgent:
    def __init__(self, tower: ControlTower):
        self.tower = tower
        self.ctx = AgentContext(
            agent_id="cleanup-bot", version="1.0.0", owner="ops-team"
        )

        # Wrap tools
        self.list_stale = wrap_tool(
            tower,
            list_stale_tickets,
            tool="ticket_system",
            action="list_stale_tickets",
            resource_type="ticket_list",
            effect=Effect.READ,
        )

        self.close = wrap_tool(
            tower,
            close_ticket,
            tool="ticket_system",
            action="close_ticket",
            resource_type="ticket",
            effect=Effect.WRITE,
        )

    def run(self):
        intent = Intent(
            action="cleanup_stale_tickets", reason="Reducing backlog of old tickets"
        )

        print("\n--- Agent: Searching for stale tickets ---")
        stale_tickets = self.list_stale(self.ctx, intent, min_age_days=90)
        print(f"Found {len(stale_tickets)} stale tickets.")

        for ticket in stale_tickets:
            print(
                f"\n--- Agent: Attempting to close {ticket['id']} "
                f"(Age: {ticket['age_days']} days, VIP: {ticket['is_vip']}) ---"
            )

            # Pass ticket metadata for policy evaluation
            metadata = {
                "ticket_age_days": ticket["age_days"],
                "is_vip": ticket["is_vip"],
            }

            try:
                result = self.close(
                    self.ctx, intent, metadata=metadata, ticket_id=ticket["id"]
                )
                print(f"Success: {result['message']}")
            except TollgateError as e:
                print(f"Blocked by Tollgate: {e}")
