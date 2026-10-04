"""
Tests for the rule checks.

Unit tests feed one rule a hand-made tool and check the result.
The integration test runs the real audit against the vulnerable
test server and checks the exact answer key.

Run from the project root:
    pytest -v
"""

import sys
from pathlib import Path

import pytest

from auditor.client import list_target_tools
from auditor.rules import (
    check_config_secrets,
    check_destructive,
    check_open_paths,
    check_suspicious_description,
    run_rules,
)

ROOT = Path(__file__).resolve().parent.parent
TEST_SERVER = ROOT / "test_servers" / "vulnerable_server.py"


def make_tool(name, description, properties=None, annotations=None):
    """Build a tool dict in the same shape the client returns."""
    return {
        "name": name,
        "description": description,
        "input_schema": {"type": "object", "properties": properties or {}},
        "annotations": annotations or {},
    }


# ---------- unit tests ----------

def test_clean_tool_has_no_findings():
    tool = make_tool("add", "Add two numbers.", {"a": {"type": "integer"}, "b": {"type": "integer"}})
    assert run_rules([tool], {}, "x") == []


def test_destructive_tool_lying_in_annotations():
    tool = make_tool("delete_file", "Delete a file.", annotations={"destructiveHint": False})
    findings = check_destructive(tool)
    assert len(findings) == 1
    assert "misleading" in findings[0].title


def test_confirm_parameter_lowers_severity():
    tool = make_tool("delete_file", "Delete a file.", {"confirm": {"type": "boolean"}})
    assert check_destructive(tool)[0].severity == "medium"


def test_restricted_path_is_not_flagged():
    tool = make_tool("read_file", "Read a log.", {"path": {"type": "string", "enum": ["app.log", "error.log"]}})
    assert check_open_paths(tool) == []


def test_profile_param_is_not_mistaken_for_file():
    # "profile" contains the letters "file" but is not a path parameter
    tool = make_tool("get_user", "Get a user.", {"profile": {"type": "string"}})
    assert check_open_paths(tool) == []


def test_single_weak_signal_is_medium():
    tool = make_tool("search", "Before calling this tool, make sure the query is short.")
    assert check_suspicious_description(tool)[0].severity == "medium"


def test_env_reference_is_not_a_secret():
    entry = {"env": {"API_KEY": "${API_KEY}"}}
    assert check_config_secrets(entry, "x") == []


def test_secret_is_masked_in_evidence():
    secret = "sk-test-FAKE1234567890abcdefFAKE"
    findings = check_config_secrets({"env": {"WEATHER_API_KEY": secret}}, "x")
    evidence = " ".join(findings[0].evidence)
    assert secret not in evidence
    assert "sk-t...FAKE" in evidence


# ---------- integration test ----------

EXPECTED = {
    ("MCP-R001", "delete_file"),
    ("MCP-R002", "read_file"),
    ("MCP-R002", "delete_file"),
    ("MCP-R003", "get_weather"),
    ("MCP-R004", "config (vulnerable-test-server)"),
}


@pytest.mark.anyio
async def test_vulnerable_server_answer_key():
    # sys.executable = the Python running pytest, so the server uses the same venv
    tools = await list_target_tools(sys.executable, [str(TEST_SERVER)])
    entry = {"env": {"WEATHER_API_KEY": "sk-test-FAKE1234567890abcdefFAKE"}}

    findings = run_rules(tools, entry, "vulnerable-test-server")

    assert {(f.rule_id, f.target) for f in findings} == EXPECTED
    flagged = {f.target for f in findings}
    assert "add" not in flagged

    # Known gap: this attack avoids every keyword our rules look for.
    # The LLM check exists to close it. If this assert ever fails,
    # a rule got smarter and the answer key should be updated.
    assert "get_forecast" not in flagged
