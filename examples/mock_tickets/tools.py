import json
from pathlib import Path

TICKETS_PATH = Path(__file__).parent / "tickets.json"


def _load_tickets() -> list[dict]:
    with TICKETS_PATH.open() as f:
        return json.load(f)


def _save_tickets(tickets: list[dict]):
    with TICKETS_PATH.open("w") as f:
        json.dump(tickets, f, indent=2)


def list_stale_tickets(min_age_days: int) -> list[dict]:
    """Returns tickets older than min_age_days."""
    tickets = _load_tickets()
    return [
        t for t in tickets if t["age_days"] >= min_age_days and t["status"] == "OPEN"
    ]


def close_ticket(ticket_id: str):
    """Closes a ticket by ID and returns trusted metadata."""
    tickets = _load_tickets()
    ticket = next((t for t in tickets if t["id"] == ticket_id), None)

    if not ticket:
        return {"status": "error", "message": f"Ticket {ticket_id} not found."}

    # Principle 3: Return trusted metadata from the source of truth
    # The interceptor or agent will use this for gating
    trusted_metadata = {
        "ticket_age_days": ticket["age_days"],
        "is_vip": ticket["is_vip"],
    }

    ticket["status"] = "CLOSED"
    _save_tickets(tickets)

    return {
        "status": "success",
        "message": f"Ticket {ticket_id} closed.",
        "trusted_metadata": trusted_metadata,
    }
