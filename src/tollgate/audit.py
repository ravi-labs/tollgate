import json
from pathlib import Path
from typing import Protocol

from .types import AuditEvent


class AuditSink(Protocol):
    """Protocol for auditing tool execution results."""

    def emit(self, event: AuditEvent) -> None:
        """Emit an audit event."""
        ...


class JsonlAuditSink:
    """Audit sink that writes to a JSONL file."""

    def __init__(self, log_path: str | Path):
        """Initialize the sink and ensure the log directory exists."""
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._f = None

    def _get_file(self):
        if self._f is None or self._f.closed:
            # line buffered
            self._f = self.log_path.open("a", encoding="utf-8", buffering=1)
        return self._f

    def emit(self, event: AuditEvent) -> None:
        """Append an audit event to the JSONL file."""
        f = self._get_file()
        f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def close(self):
        """Close the file handle."""
        if self._f and not self._f.closed:
            self._f.close()

    def __del__(self):
        self.close()
