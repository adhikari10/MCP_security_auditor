"""
Run a full audit: connect to each server in a config, list its tools,
run the rule checks, and print the findings.

Usage (from the project root):
    python -m auditor.audit test_servers/test_config.json
"""

import asyncio
import sys

from auditor.client import list_target_tools, load_server_config
from auditor.rules import run_rules

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def print_report(server_name: str, tools: list[dict], findings, error: str | None) -> None:
    print(f"\n=== Audit: {server_name} ===")
    if error:
        print(f"Could not list tools ({error}). Config checks still ran.")
    else:
        print(f"Tools found: {len(tools)}")

    for f in sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity]):
        print(f"\n[{f.severity.upper()}] {f.rule_id}  {f.target}")
        print(f"  {f.title}")
        for line in f.evidence:
            print(f"    - {line}")

    flagged = {f.target for f in findings}
    clean = [t["name"] for t in tools if t["name"] not in flagged]
    print(f"\nNo findings: {', '.join(clean) if clean else 'none'}")
    print(f"Total findings: {len(findings)}")


async def audit(config_path: str) -> None:
    for name, entry in load_server_config(config_path).items():
        tools, error = [], None
        try:
            tools = await list_target_tools(entry["command"], entry.get("args", []))
        except TimeoutError:
            error = "timed out"
        except Exception as e:
            error = repr(e)
        # Config checks don't need a live server, so a failed connection
        # still gives a partial audit instead of nothing.
        findings = run_rules(tools, entry, name)
        print_report(name, tools, findings, error)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m auditor.audit <config.json>")
        sys.exit(1)
    asyncio.run(audit(sys.argv[1]))