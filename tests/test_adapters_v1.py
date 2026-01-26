from tollgate import Effect
from tollgate.interceptors.langchain import LangChainAdapter
from tollgate.registry import ToolRegistry


class MockLCTool:
    def __init__(self, name):
        self.name = name
        self.description = "desc"

def test_langchain_adapter_normalization(tmp_path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("""
tools:
  "langchain:my_tool":
    effect: "delete"
    resource_type: "file"
""")
    registry = ToolRegistry(manifest)
    adapter = LangChainAdapter(registry)
    
    tool = MockLCTool("my_tool")
    tool_input = {"path": "/etc/passwd"}
    
    normalized = adapter.normalize((tool, tool_input))
    
    assert normalized.request.tool == "langchain"
    assert normalized.request.action == "my_tool"
    assert normalized.request.effect == Effect.DELETE
    assert normalized.request.resource_type == "file"
    assert normalized.request.params == tool_input
    assert normalized.request.manifest_version is not None

