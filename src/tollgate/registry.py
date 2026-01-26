import hashlib
from pathlib import Path

import yaml

from .types import Effect


class ToolRegistry:
    """A registry of trusted tool metadata."""

    def __init__(self, manifest_path: str | Path):
        self.path = Path(manifest_path)
        if not self.path.exists():
            raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

        with self.path.open("r") as f:
            content = f.read()
            self.data = yaml.safe_load(content)
            if not self.data:
                self.data = {}
            # Use content hash as manifest version if not provided
            self.version = str(
                self.data.get(
                    "version", hashlib.sha256(content.encode()).hexdigest()[:8]
                )
            )
        self.tools = self.data.get("tools", {})
        self._validate_manifest()

    def _validate_manifest(self):
        """Basic validation of manifest structure."""
        if not isinstance(self.tools, dict):
            raise ValueError("Manifest 'tools' must be a dictionary.")

        for key, entry in self.tools.items():
            if not isinstance(entry, dict):
                raise ValueError(f"Tool entry '{key}' must be a dictionary.")
            if "effect" in entry:
                try:
                    Effect(entry["effect"])
                except ValueError as e:
                    raise ValueError(
                        f"Invalid effect '{entry['effect']}' for tool '{key}'."
                    ) from e

    def resolve_tool(self, tool_key: str) -> tuple[Effect, str, str | None]:
        """
        Resolve tool key to (effect, resource_type, manifest_version).
        Returns (UNKNOWN, "unknown", None) if not found.
        """
        meta = self.tools.get(tool_key)
        if not meta:
            return Effect.UNKNOWN, "unknown", None

        effect = Effect(meta.get("effect", "unknown"))
        resource_type = meta.get("resource_type", "unknown")
        return effect, resource_type, self.version
