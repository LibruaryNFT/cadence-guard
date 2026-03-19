"""
Cadence Guard MCP Server

A Model Context Protocol (MCP) server that exposes Cadence Guard's security
scanner and checklist as tools for AI assistants. Runs locally on your machine —
no hosting or cloud services needed.

Usage:
    pip install mcp
    python mcp/server.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print(
        "Error: MCP package not installed.\n"
        "Install it with: pip install mcp\n"
        "Then run: python mcp/server.py",
        file=sys.stderr,
    )
    sys.exit(1)

REPO_ROOT = Path(__file__).parent.parent
SCANNER_PATH = REPO_ROOT / "scanner" / "cadence_audit.go"
CHECKLIST_PATH = REPO_ROOT / "checklist" / "security-checklist.md"
RULES_PATH = REPO_ROOT / "rules" / "cadence-guard-rules.md"

mcp = FastMCP(
    "cadence-guard",
    description="Cadence smart contract security scanner and audit tools",
)


@mcp.tool()
def scan_contracts(
    target_dir: str,
    severity: str = "low",
    timeout_seconds: int = 120,
) -> str:
    """
    Run the Cadence Guard static security scanner on a directory of .cdc files.

    Args:
        target_dir: Path to directory containing .cdc contract files
        severity: Minimum severity to report (critical, high, medium, low, info). Default: low
        timeout_seconds: Maximum time to run in seconds. Default: 120, max: 300

    Returns:
        JSON array of findings, each with rule_id, severity, file, line, description, and context.
        Empty array if no findings.
    """
    if severity not in ("critical", "high", "medium", "low", "info"):
        return json.dumps({"error": f"Invalid severity: {severity}. Use critical/high/medium/low/info"})

    timeout_seconds = min(timeout_seconds, 300)

    if not os.path.isdir(target_dir):
        return json.dumps({"error": f"Directory not found: {target_dir}"})

    try:
        result = subprocess.run(
            ["go", "run", str(SCANNER_PATH), "--json", "--severity", severity, target_dir],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        # Scanner returns exit code 1 for high+ findings, which is expected
        output = result.stdout.strip()
        if not output:
            return json.dumps([])

        # Validate it's proper JSON
        findings = json.loads(output)
        return json.dumps(findings, indent=2)

    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Scanner timed out after {timeout_seconds} seconds"})
    except FileNotFoundError:
        return json.dumps({"error": "Go is not installed or not on PATH. Install Go from https://go.dev/dl/"})
    except json.JSONDecodeError:
        return json.dumps({"error": "Scanner produced invalid output", "raw": result.stdout[:500]})


@mcp.tool()
def get_checklist() -> str:
    """
    Get the full Cadence Guard security audit checklist.

    Returns the 10-section, 50+ item manual audit checklist as markdown.
    Use this to walk through a structured security review of Cadence contracts.
    """
    if not CHECKLIST_PATH.exists():
        return "Error: Checklist not found. Ensure cadence-guard repo is intact."
    return CHECKLIST_PATH.read_text(encoding="utf-8")


@mcp.tool()
def get_rules() -> str:
    """
    Get the Cadence Guard security and code quality rules.

    Returns structured rules covering security (access control, resource safety,
    token operations, storage, input validation, randomness, DeFi, cross-VM)
    and code quality (naming, documentation, patterns). Use these rules as
    context when reviewing or generating Cadence smart contracts.
    """
    if not RULES_PATH.exists():
        return "Error: Rules file not found. Ensure cadence-guard repo is intact."
    return RULES_PATH.read_text(encoding="utf-8")


@mcp.tool()
def get_finding_template() -> str:
    """
    Get the finding documentation template.

    Returns a markdown template for documenting security audit findings
    with fields for severity, root cause, impact, PoC, and recommendation.
    """
    template_path = REPO_ROOT / "templates" / "finding-template.md"
    if not template_path.exists():
        return "Error: Template not found. Ensure cadence-guard repo is intact."
    return template_path.read_text(encoding="utf-8")


@mcp.tool()
def explain_rule(rule_id: str) -> str:
    """
    Explain what a specific scanner rule checks for and why it matters.

    Args:
        rule_id: The rule ID (e.g., ACC-001, TOK-002, RES-001)

    Returns:
        Explanation of the rule, what it detects, why it's a security concern,
        and how to fix flagged code.
    """
    rules = {
        "ACC-001": {
            "name": "Sensitive function with access(all)",
            "severity": "high",
            "what": "Detects functions like withdraw, deposit, burn, mint, transfer, destroy, or admin that use access(all) instead of entitlement-gated access.",
            "why": "In Cadence 1.0, access(all) means anyone can call the function. Sensitive operations must require specific entitlements (e.g., access(Withdraw)) so only authorized callers can invoke them.",
            "fix": "Replace access(all) with an entitlement: access(Withdraw) fun withdraw(...) or access(Admin) fun setConfig(...).",
        },
        "ACC-002": {
            "name": "Deprecated 'pub' modifier",
            "severity": "medium",
            "what": "Detects use of the pre-Cadence 1.0 'pub' keyword.",
            "why": "'pub' was replaced by access(all) in Cadence 1.0. Using it indicates the contract hasn't been updated to the current language version.",
            "fix": "Replace 'pub fun' with 'access(all) fun' or an appropriate entitlement. Review each case — many 'pub' functions should actually be entitlement-gated.",
        },
        "ACC-003": {
            "name": "Deprecated 'pub var'",
            "severity": "medium",
            "what": "Detects 'pub var' field declarations.",
            "why": "Same as ACC-002 — deprecated syntax. Additionally, public mutable fields are rarely appropriate; consider access(self) with a getter.",
            "fix": "Replace with access(all) var (if truly needed) or access(self) var with an access(all) view getter function.",
        },
        "ACC-004": {
            "name": "Admin/setter with access(all)",
            "severity": "high",
            "what": "Detects functions with admin/owner/set/update in the name that use access(all).",
            "why": "Administrative functions should never be publicly callable. This is a direct path to unauthorized state modification.",
            "fix": "Use access(Admin) or access(contract) to restrict to authorized callers only.",
        },
        "RES-001": {
            "name": "Destroy without balance zeroing",
            "severity": "high",
            "what": "Detects destroy() calls without nearby code that zeros a balance.",
            "why": "Destroying a vault with nonzero balance permanently burns tokens without updating totalSupply, breaking supply invariants.",
            "fix": "Zero the balance before destroying, or add a pre-condition: pre { self.balance == 0.0 }.",
        },
        "RES-002": {
            "name": "Force-unwrap move",
            "severity": "medium",
            "what": "Detects the <-! operator (force-unwrap move on optional resource).",
            "why": "If the optional is nil, the resource is destroyed. This can silently lose resources if nil is possible.",
            "fix": "Use if-let or a nil check before moving: if let res <- optionalResource { ... }.",
        },
        "RES-003": {
            "name": "Missing view annotation",
            "severity": "info",
            "what": "Detects functions that may not mutate state but lack the 'view' annotation.",
            "why": "Marking non-mutating functions as 'view' enforces purity at the type level, preventing accidental state changes.",
            "fix": "Add 'view' before 'fun': access(all) view fun getBalance(): UFix64.",
        },
        "TOK-001": {
            "name": "Deposit without type guard",
            "severity": "high",
            "what": "Detects deposit functions that don't verify the incoming vault's type.",
            "why": "Without a type check, an attacker could deposit a different token type, corrupting the vault's state.",
            "fix": "Add: assert(from.getType() == Type<@YourToken.Vault>(), message: \"Wrong vault type\").",
        },
        "TOK-002": {
            "name": "Unchecked minting",
            "severity": "medium",
            "what": "Detects mint functions without nearby totalSupply updates.",
            "why": "Minting without tracking totalSupply breaks supply accounting and can hide inflation attacks.",
            "fix": "Increment totalSupply in every mint path. Ensure the mint function is entitlement-gated.",
        },
        "TOK-003": {
            "name": "Unchecked burning",
            "severity": "high",
            "what": "Detects burn functions without nearby totalSupply or balance updates.",
            "why": "Burning without decrementing totalSupply creates ghost supply. Not zeroing balance before destroy can burn real value.",
            "fix": "Decrement totalSupply by the burned amount. Zero the vault balance before destroying.",
        },
        "TOK-004": {
            "name": "Division before multiplication",
            "severity": "medium",
            "what": "Detects arithmetic where division happens before multiplication.",
            "why": "UFix64 has only 8 decimal places. Dividing first truncates precision that multiplication could have preserved.",
            "fix": "Reorder to multiply first: (a * b) / c instead of (a / c) * b. Note: Cadence panics on overflow, so verify the multiplication won't overflow.",
        },
        "STO-001": {
            "name": "String interpolation in storage path",
            "severity": "medium",
            "what": "Detects storage paths that include function calls or interpolation.",
            "why": "User-controlled path components can collide with other users' data, enabling storage manipulation.",
            "fix": "Use fixed, deterministic storage paths. If dynamic paths are needed, validate and namespace them.",
        },
        "STO-002": {
            "name": "Unchecked storage borrow",
            "severity": "low",
            "what": "Detects .borrow<> calls without nearby nil handling (?? or if let).",
            "why": "Borrow returns nil if the type doesn't match or nothing is stored at that path. Unhandled nil causes a panic.",
            "fix": "Use: let ref = account.storage.borrow<&T>(from: path) ?? panic(\"Not found\").",
        },
        "INP-001": {
            "name": "Public function without pre-conditions",
            "severity": "medium",
            "what": "Detects access(all) functions with parameters but no nearby pre {} block.",
            "why": "Public functions are the entry point for attackers. Without pre-conditions, invalid inputs can cause unexpected behavior.",
            "fix": "Add pre { } block validating all parameters: ranges, non-nil, non-empty, length limits.",
        },
        "INP-002": {
            "name": "Nil-check + force-unwrap anti-pattern",
            "severity": "medium",
            "what": "Detects the pattern: if x != nil { ... x! ... }.",
            "why": "This is fragile — if code between the check and unwrap changes x, the force-unwrap can panic. if-let is atomic.",
            "fix": "Replace with: if let value = x { ... value ... }.",
        },
        "INP-003": {
            "name": "Unbounded dictionary iteration",
            "severity": "low",
            "what": "Detects for loops iterating over self.*.keys (dictionary keys).",
            "why": "If an attacker can grow the dictionary (e.g., by creating entries), they can make this loop exceed computation limits (DoS).",
            "fix": "Add size caps, use pagination, or restrict who can add entries to the dictionary.",
        },
        "CAP-001": {
            "name": "Capability publishing",
            "severity": "info",
            "what": "Flags all capabilities.publish calls for manual review.",
            "why": "Publishing a capability makes it accessible to others. Review what type and entitlements are exposed.",
            "fix": "Verify the published type exposes only what's intended. Use specific entitlements, not broad access.",
        },
        "CAP-002": {
            "name": "Interface-restricted capability",
            "severity": "medium",
            "what": "Detects capabilities published with interface-only types like &{Interface}.",
            "why": "In Cadence 1.0, interface restriction alone is NOT a security boundary. Anyone can borrow the concrete type. Use entitlements.",
            "fix": "Publish with entitlements: issue<auth(Withdraw) &Vault> instead of issue<&{FungibleToken.Receiver}>.",
        },
        "RND-001": {
            "name": "revertibleRandom usage",
            "severity": "high",
            "what": "Detects any use of revertibleRandom().",
            "why": "revertibleRandom in the same transaction as the commit is manipulable — miners/validators can influence the outcome. Requires commit-reveal with at least 1 block separation.",
            "fix": "Implement commit-reveal: user commits in block N, reveal uses revertibleRandom in block N+1 or later.",
        },
        "EVM-001": {
            "name": "Cross-VM call",
            "severity": "info",
            "what": "Flags any EVM.* calls for manual review.",
            "why": "Cross-VM operations have unique risks: atomicity (partial failure), precision (UFix64 vs uint256), and reentrancy (EVM callbacks into Cadence).",
            "fix": "Review for atomicity, precision preservation, and reentrancy guards. See checklist §10.",
        },
    }

    rule_id_upper = rule_id.upper().strip()
    if rule_id_upper in rules:
        r = rules[rule_id_upper]
        return (
            f"## {rule_id_upper}: {r['name']}\n\n"
            f"**Severity:** {r['severity']}\n\n"
            f"**What it detects:** {r['what']}\n\n"
            f"**Why it matters:** {r['why']}\n\n"
            f"**How to fix:** {r['fix']}"
        )
    else:
        available = ", ".join(sorted(rules.keys()))
        return f"Unknown rule ID: {rule_id}. Available rules: {available}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
