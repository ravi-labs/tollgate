from tollgate import Effect, ToolRegistry


def test_registry_resolution(tmp_path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("""
version: "1.0.0"
tools:
  "mcp:server.tool":
    effect: "write"
    resource_type: "disk"
""")

    registry = ToolRegistry(manifest)
    assert registry.version == "1.0.0"

    effect, res, ver = registry.resolve_tool("mcp:server.tool")
    assert effect == Effect.WRITE
    assert res == "disk"
    assert ver == "1.0.0"

    effect, res, ver = registry.resolve_tool("unknown:tool")
    assert effect == Effect.UNKNOWN
    assert ver is None
