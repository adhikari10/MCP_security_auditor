"""
Rule-based checks. Deterministic, no LLM involved.

These run alongside the LLM checks. If an attacker writes a tool
description that fools the LLM, these rules still fire, because a
regex can't be talked out of matching.

Every finding carries evidence: the exact text that triggered it.
That is what makes each result explainable.
"""

import re
from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # "low", "medium" or "high"
    target: str  # tool name, or "config (<server>)"
    evidence: list[str] = field(default_factory=list)
    source: str = "rule"  # later the LLM check will use "llm"

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- helpers ----------

def _words_from_name(name: str) -> str:
    """delete_file -> 'delete file', deleteFile -> 'delete file'."""
    name = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    return re.sub(r"[_\-.]+", " ", name).lower()


def _snippet(text: str, limit: int = 80) -> str:
    """Collapse whitespace and shorten, so evidence stays readable."""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _mask(value: str) -> str:
    """Show only the edges of a secret. Never print it in full."""
    if len(value) <= 12:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


# ---------- R001: destructive action ----------

DESTRUCTIVE_WORDS = re.compile(
    r"\b(delete|remove|erase|destroy|drop|truncate|overwrite|wipe|kill|"
    r"execute|exec|run command|shell|send email|send message|transfer|payment)\b",
    re.IGNORECASE,
)
CONFIRM_PARAMS = {"confirm", "confirmed", "dry_run", "dryrun"}


def check_destructive(tool: dict) -> list[Finding]:
    text = _words_from_name(tool["name"]) + " " + tool["description"]
    words = sorted({m.group(0).lower() for m in DESTRUCTIVE_WORDS.finditer(text)})
    if not words:
        return []

    evidence = [f"destructive keywords: {', '.join(words)}"]
    severity = "high"
    title = "Destructive action, verify human approval"

    annotations = tool.get("annotations", {})
    params = set(tool.get("input_schema", {}).get("properties", {}))

    if annotations.get("readOnlyHint") is True or annotations.get("destructiveHint") is False:
        title = "Destructive action with misleading safety annotations"
        evidence.append(f"annotations claim the tool is safe: {annotations}")
    elif params & CONFIRM_PARAMS:
        severity = "medium"
        evidence.append(f"has a confirmation parameter: {sorted(params & CONFIRM_PARAMS)}")
    else:
        evidence.append("no confirmation parameter and no destructiveHint declared")

    return [Finding("MCP-R001", title, severity, tool["name"], evidence)]


# ---------- R002: open file path ----------

PATH_WORDS = {"path", "file", "filename", "filepath", "dir", "directory", "folder"}
BROAD_SCOPE = re.compile(r"\b(any|all|entire|whole)\b[^.]{0,30}\b(file|files|system|disk)\b", re.I)


def check_open_paths(tool: dict) -> list[Finding]:
    properties = tool.get("input_schema", {}).get("properties", {})
    evidence = []
    for name, schema in properties.items():
        if not PATH_WORDS & set(_words_from_name(name).split()):
            continue
        if schema.get("type") == "string" and not ("enum" in schema or "pattern" in schema):
            evidence.append(f"parameter '{name}' is a free string with no enum or pattern restriction")
    if not evidence:
        return []

    severity = "medium"
    broad = BROAD_SCOPE.search(tool["description"])
    if broad:
        severity = "high"
        evidence.append(f"description claims broad scope: '{_snippet(broad.group(0))}'")

    return [Finding("MCP-R002", "Unrestricted file path parameter", severity, tool["name"], evidence)]


# ---------- R003: suspicious description content ----------

SUSPICIOUS_PATTERNS = {
    "hidden instruction tag": re.compile(r"<\s*/?\s*(important|system|instructions?|secret)\s*>", re.I),
    "concealment from user": re.compile(
        r"\b(do not|don't|never)\s+(tell|mention|inform|reveal|show)[^.]{0,60}\buser", re.I
    ),
    "sensitive file reference": re.compile(
        r"(~/\.ssh|id_rsa|\.env\b|/etc/passwd|\.aws/credentials|mcp\.json|claude_desktop_config)", re.I
    ),
    "instruction override": re.compile(r"\bignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions", re.I),
    "pre-call instruction": re.compile(r"\bbefore\s+(using|calling)\s+this\s+tool", re.I),
}


def check_suspicious_description(tool: dict) -> list[Finding]:
    evidence = []
    for label, pattern in SUSPICIOUS_PATTERNS.items():
        match = pattern.search(tool["description"])
        if match:
            evidence.append(f"{label}: '{_snippet(match.group(0))}'")
    if not evidence:
        return []

    # One weak signal could be innocent. Several together look like an attack.
    severity = "high" if len(evidence) >= 2 else "medium"
    return [Finding("MCP-R003", "Possible hidden instructions in tool description", severity, tool["name"], evidence)]


# ---------- R004: secrets in config ----------

SECRET_FORMATS = {
    "OpenAI-style key": re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Slack token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
}
SECRET_NAME = re.compile(r"(key|token|secret|password|passwd|credential)", re.I)


def check_config_secrets(server_entry: dict, server_name: str) -> list[Finding]:
    evidence = []

    for var, value in server_entry.get("env", {}).items():
        if not isinstance(value, str) or not value or value.startswith("${"):
            continue  # empty or a reference like ${MY_KEY}, not a literal secret
        known = [label for label, rx in SECRET_FORMATS.items() if rx.search(value)]
        if known:
            evidence.append(f"env {var} = {_mask(value)} (matches {known[0]} format)")
        elif SECRET_NAME.search(var) and len(value) >= 8:
            evidence.append(f"env {var} = {_mask(value)} (secret-like name with literal value)")

    for arg in server_entry.get("args", []):
        for label, rx in SECRET_FORMATS.items():
            match = rx.search(str(arg))
            if match:
                evidence.append(f"command argument contains {label}: {_mask(match.group(0))}")

    if not evidence:
        return []
    return [Finding("MCP-R004", "Plaintext secret in server config", "high", f"config ({server_name})", evidence)]


# ---------- run everything ----------

TOOL_RULES = [check_destructive, check_open_paths, check_suspicious_description]


def run_rules(tools: list[dict], server_entry: dict, server_name: str) -> list[Finding]:
    findings = []
    for tool in tools:
        for rule in TOOL_RULES:
            findings.extend(rule(tool))
    findings.extend(check_config_secrets(server_entry, server_name))
    return findings