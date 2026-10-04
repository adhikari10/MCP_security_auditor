"""
Step 2: connect to a target MCP server over stdio and list its tools.

Everything returned here is untrusted data from the target server.
We only read it. We never follow instructions found in it,
and we never call the target's tools.
"""

import asyncio
import json
import sys
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TIMEOUT_SECONDS = 15


def load_server_config(config_path: str) -> dict[str, dict]:
    """Read an MCP client config file and return its server entries."""
    data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    return data.get("mcpServers", {})


async def list_target_tools(command: str, args: list[str]) -> list[dict]:
    """Launch the target server, ask for its tool list, return plain dicts."""
    # Note: we deliberately do NOT pass the config's "env" block here.
    # It can contain secrets, and the auditor has no reason to hand
    # secrets to a server it doesn't trust.
    params = StdioServerParameters(command=command, args=args)

    # A malicious or broken server could hang forever. Give up after a limit.
    with anyio.fail_after(TIMEOUT_SECONDS):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()

    # Convert SDK objects to plain dicts so later steps (rules, LLM, RAG)
    # don't depend on the SDK's internal types.
    return [
        {
            "name": tool.name,
            "description": tool.description or "",
            "input_schema": tool.input_schema,
            # Optional hints a server can declare, e.g. destructiveHint.
            # Useful later, but still untrusted: a server can lie about them.
            "annotations": tool.annotations.model_dump(exclude_none=True)
            if tool.annotations
            else {},
        }
        for tool in result.tools
    ]


async def main(config_path: str) -> None:
    servers = load_server_config(config_path)
    for name, entry in servers.items():
        print(f"=== {name} ===")
        try:
            tools = await list_target_tools(entry["command"], entry.get("args", []))
        except TimeoutError:
            print(f"  Timed out after {TIMEOUT_SECONDS}s")
            continue
        except Exception as e:
            print(f"  Could not connect: {e!r}")
            continue
        print(json.dumps(tools, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python auditor/client.py <config.json>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))