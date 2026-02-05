"""Agent identity verification via HMAC signing.

Provides utilities to sign and verify AgentContext instances so that
the ControlTower can trust agent_id claims are authentic.

Usage:
    from tollgate.verification import sign_agent_context, make_verifier

    # At agent startup — sign the context
    ctx = sign_agent_context(
        AgentContext(agent_id="my-agent", version="1.0", owner="team-a"),
        secret_key=b"shared-secret",
    )

    # At ControlTower — verify incoming contexts
    tower = ControlTower(
        policy=policy,
        approver=approver,
        audit=audit,
        verify_fn=make_verifier(b"shared-secret"),
    )
"""

import hashlib
import hmac
from dataclasses import replace
from typing import Any

from .types import AgentContext


def _compute_signature(agent_ctx: AgentContext, secret_key: bytes) -> str:
    """Compute HMAC-SHA256 over the canonical agent identity fields."""
    payload = f"{agent_ctx.agent_id}|{agent_ctx.version}|{agent_ctx.owner}"
    return hmac.new(secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_agent_context(agent_ctx: AgentContext, secret_key: bytes) -> AgentContext:
    """Return a new AgentContext with an HMAC signature in metadata.

    The signature covers ``agent_id``, ``version``, and ``owner``.
    It is stored under ``metadata["_signature"]``.
    """
    sig = _compute_signature(agent_ctx, secret_key)
    new_meta: dict[str, Any] = {**agent_ctx.metadata, "_signature": sig}
    return replace(agent_ctx, metadata=new_meta)


def verify_agent_context(agent_ctx: AgentContext, secret_key: bytes) -> bool:
    """Verify that the AgentContext signature is valid.

    Returns True if the signature matches, False otherwise.
    Returns False if no signature is present.
    """
    sig = agent_ctx.metadata.get("_signature")
    if not sig or not isinstance(sig, str):
        return False
    expected = _compute_signature(agent_ctx, secret_key)
    return hmac.compare_digest(sig, expected)


def make_verifier(
    secret_key: bytes,
) -> "callable[[AgentContext], bool]":
    """Create a verification function suitable for ControlTower.verify_fn.

    Example:
        tower = ControlTower(
            ...,
            verify_fn=make_verifier(b"my-secret"),
        )
    """

    def _verify(agent_ctx: AgentContext) -> bool:
        return verify_agent_context(agent_ctx, secret_key)

    return _verify
