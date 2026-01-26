class TollgateError(Exception):
    """Base exception for all Tollgate errors."""

    pass


class TollgateDenied(TollgateError):  # noqa: N818
    """Raised when a tool call is explicitly denied by policy."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Tool call denied: {reason}")


class TollgateApprovalDenied(TollgateError):  # noqa: N818
    """Raised when a human-in-the-loop approval is denied."""

    def __init__(self, reason: str = "Approval denied by human."):
        self.reason = reason
        super().__init__(reason)


class TollgateDeferred(TollgateError):  # noqa: N818
    """Raised when a tool call is deferred (e.g., waiting for async approval)."""

    def __init__(self, approval_id: str):
        self.approval_id = approval_id
        super().__init__(f"Tool call deferred. Approval ID: {approval_id}")

