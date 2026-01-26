import hashlib
from pathlib import Path
from typing import Any

import yaml

from .types import Effect


class ToolRegistry:
    """A registry of trusted tool metadata."""

    def __init__(self, manifest_path: str | Path):
        self.path = Path(manifest_path)
        with self.path.open("r") as f:
            content = f.read()
            self.data = yaml.safe_load(content)
            # Use content hash as manifest version if not provided
            self.version = self.data.get(
                "version", hashlib.sha256(content.encode()).hexdigest()[:8]
            )
        self.tools = self.data.get("tools", {})

    def get_tool_metadata(self, tool_key: str) -> dict[str, Any] | None:
        """
        Lookup metadata for a tool by its key.
        Keys are typically formatted as:
        - mcp:{server}.{tool_name}
        - langchain:{tool_name}
        - openai:{tool_name}
        """
        return self.tools.get(tool_key)

    def resolve_tool(self, tool_key: str) -> tuple[Effect, str, str | None]:
        """
        Resolve tool key to (effect, resource_type, manifest_version).
        Returns UNKNOWN if not found.
        """
        meta = self.get_tool_metadata(tool_key)
        if not meta:
            return Effect.UNKNOWN, "unknown", None

        effect = Effect(meta.get("effect", "unknown"))
        resource_type = meta.get("resource_type", "unknown")
        return effect, resource_type, self.version
