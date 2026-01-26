from typing import Any

from ..registry import ToolRegistry
from ..tower import ControlTower
from ..types import NormalizedToolCall, ToolRequest
from .base import TollgateInterceptor


class LangChainAdapter:
    """Adapter for LangChain tools."""

    def __init__(self, registry: ToolRegistry):
        self.registry = registry

    def normalize(self, tool_call: Any) -> NormalizedToolCall:
        # tool_call is expected to be (tool, tool_input) or (tool, tool_input, kwargs)
        if len(tool_call) == 3:
            tool, tool_input, kwargs = tool_call
        else:
            tool, tool_input = tool_call
            kwargs = {}

        tool_name = getattr(tool, "name", str(tool))
        registry_key = f"langchain:{tool_name}"

        effect, resource_type, manifest_version = self.registry.resolve_tool(
            registry_key
        )

        metadata = kwargs.get("metadata", {})

        params = tool_input if isinstance(tool_input, dict) else {"input": tool_input}

        request = ToolRequest(
            tool="langchain",
            action=tool_name,
            resource_type=resource_type,
            effect=effect,
            params=params,
            metadata=metadata,
            manifest_version=manifest_version,
        )

        async def _exec_async():
            if hasattr(tool, "ainvoke"):
                return await tool.ainvoke(tool_input)
            return await tool.arun(tool_input)

        def _exec_sync():
            if hasattr(tool, "invoke"):
                return tool.invoke(tool_input)
            return tool.run(tool_input)

        return NormalizedToolCall(
            request=request, exec_async=_exec_async, exec_sync=_exec_sync
        )


def guard_tools(
    tools: list[Any], tower: ControlTower, registry: ToolRegistry
) -> list[Any]:
    """Wrap a list of LangChain tools with Tollgate."""
    adapter = LangChainAdapter(registry)
    interceptor = TollgateInterceptor(tower, adapter)

    class GuardedTool:
        def __init__(self, tool):
            self.tool = tool
            self.name = tool.name
            self.description = tool.description

        async def ainvoke(self, tool_input, agent_ctx=None, intent=None, **kwargs):
            if agent_ctx is None or intent is None:
                return await self.tool.ainvoke(tool_input, **kwargs)

            # Pass extra kwargs (like metadata) to the interceptor
            return await interceptor.intercept_async(
                agent_ctx, intent, (self.tool, tool_input, kwargs)
            )

        def invoke(self, tool_input, agent_ctx=None, intent=None, **kwargs):
            if agent_ctx is None or intent is None:
                return self.tool.invoke(tool_input, **kwargs)

            return interceptor.intercept(
                agent_ctx, intent, (self.tool, tool_input, kwargs)
            )

    return [GuardedTool(t) for t in tools]
