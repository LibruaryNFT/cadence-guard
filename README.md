# Cadence Guard

Community-driven security and code quality framework for [Cadence](https://cadence-lang.org/) smart contracts on the [Flow](https://flow.com/) blockchain.

**Why this exists:** Security knowledge for Cadence is scattered across docs, blog posts, audit reports, and tribal knowledge. Cadence Guard aggregates this into a single, structured, AI-friendly framework that works with the way software is built today — with AI assistants, automated scanners, and structured checklists.

**This is a community project.** Anyone can contribute rules, scanner patterns, checklist items, or improvements. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 60-Second Quick Start

```bash
# Clone
git clone https://github.com/LibruaryNFT/cadence-guard.git
cd cadence-guard

# Scan your contracts (requires Go)
go run scanner/cadence_audit.go /path/to/your/contracts/

# Try it on the included examples
go run scanner/cadence_audit.go ./examples/
```

That's it. The scanner outputs findings sorted by severity. See [How to Use](#how-to-use) below for AI integration, MCP setup, and more.

---

## What's Inside

| Component | Path | Description |
|-----------|------|-------------|
| **Static Scanner** | `scanner/cadence_audit.go` | 21-rule Go scanner, catches security anti-patterns in `.cdc` files |
| **Security Checklist** | `checklist/security-checklist.md` | 10-section, 50+ item manual audit walkthrough |
| **AI Rules** | `rules/` | Security & code quality rules for Claude Code, Cursor, and any LLM |
| **MCP Server** | `mcp/server.py` | Model Context Protocol server — lets AI tools run the scanner directly |
| **Finding Template** | `templates/finding-template.md` | Standardized format for documenting audit findings |
| **Examples** | `examples/` | Vulnerable + remediated contracts showing what the scanner catches |

---

## What It Looks For

### Security (scanner + checklist)

| Category | What It Catches | Scanner Rules | Checklist Section |
|----------|----------------|---------------|-------------------|
| **Access Control** | `access(all)` on sensitive functions, deprecated `pub`, unprotected admin ops, missing entitlements | ACC-001 – ACC-004 | §1 (8 items) |
| **Resource Safety** | Destroy without balance zeroing, force-unwrap moves, missing `view` annotations, resource linearity violations | RES-001 – RES-003 | §2 (5 items) |
| **Token / Vault Ops** | Missing deposit type guards, unchecked mint/burn, total supply inconsistency, precision loss (divide-before-multiply) | TOK-001 – TOK-004 | §3 (7 items) |
| **Storage** | Path collision via interpolation, unchecked borrows, TOCTOU on storage references | STO-001 – STO-002 | §4 (6 items) |
| **Input Validation** | Public functions without pre-conditions, nil+force-unwrap anti-pattern, unbounded loops (DoS), error-induced DoS | INP-001 – INP-003 | §5 (8 items) |
| **Capabilities** | Capability publishing review, interface-only restriction (not secure in Cadence 1.0) | CAP-001 – CAP-002 | §1 |
| **Contract Updates** | Entitlement weakening via upgrade, kind confusion, interface default function risks | — | §6 (4 items) |
| **Randomness** | `revertibleRandom` without commit-reveal, predictable seeds, abortable reveals | RND-001 | §7 (3 items) |
| **Resilience** | Missing emergency pause, side effects in logical expressions | — | §8 (2 items) |
| **DeFi** | Internal vs actual balance mismatch, AMM spot price as oracle, missing oracle sanity checks | — | §9 (4 items) |
| **Cross-VM / EVM** | Atomicity, UFix64↔uint256 precision, reentrancy through EVM callbacks, supply invariants | EVM-001 | §10 (5 items) |

### Code Quality (AI rules + checklist)

| Category | What It Checks |
|----------|---------------|
| **Access Modifiers** | `view` on non-mutating functions, `access(self)` preference, `let` vs `var` |
| **Naming** | Descriptive names, plural for collections, named constants instead of magic numbers |
| **Documentation** | Comment the "why", document public functions, add argument labels |
| **Patterns** | Checks-Effects-Interactions, pre/post conditions, avoid unnecessary load/save |
| **Hygiene** | No debug code, no TODOs in critical paths, no commented-out logic |

---

## How to Use

There are several ways to use Cadence Guard depending on your workflow. Pick what fits you best — they all work independently.

### Option 1: Run the Scanner Directly

**Requirements:** [Go](https://go.dev/dl/) installed.

```bash
# Clone the repo
git clone https://github.com/LibruaryNFT/cadence-guard.git
cd cadence-guard

# Scan your contracts (replace path with your contracts directory)
go run scanner/cadence_audit.go /path/to/your/contracts/

# Only show high and critical severity
go run scanner/cadence_audit.go --severity high /path/to/your/contracts/

# JSON output (for CI pipelines or tooling)
go run scanner/cadence_audit.go --json /path/to/your/contracts/
```

**Exit codes:** `0` = no high/critical findings, `1` = high or critical findings. Use this in CI to block merges on security issues.

**Example CI step (GitHub Actions):**
```yaml
- name: Cadence Guard Security Scan
  run: go run scanner/cadence_audit.go --severity high --json ./contracts/
```

---

### Option 2: Use with Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) automatically loads `CLAUDE.md` from any repo root.

**Method A — Clone into your project (recommended):**
```bash
# From your Cadence project root
git clone https://github.com/LibruaryNFT/cadence-guard.git .cadence-guard

# Claude Code will see .cadence-guard/CLAUDE.md when you reference it
# Ask Claude: "Review my contracts using the cadence-guard checklist"
```

**Method B — Add as MCP server (gives Claude the scanner as a tool):**

Add this to your Claude Code MCP settings (`~/.claude/settings.json` or project `.claude/settings.json`):

```json
{
  "mcpServers": {
    "cadence-guard": {
      "command": "python",
      "args": ["<path-to-cadence-guard>/mcp/server.py"]
    }
  }
}
```

Then Claude Code can directly run the scanner, retrieve the checklist, and explain rules — all within your conversation. The MCP server runs locally on your machine, no hosting needed.

**Available MCP tools:**
| Tool | What It Does |
|------|-------------|
| `scan_contracts` | Run the static scanner on a directory, returns JSON findings |
| `get_checklist` | Get the full 50+ item security checklist |
| `get_rules` | Get all security and code quality rules |
| `get_finding_template` | Get the finding documentation template |
| `explain_rule` | Explain what a specific rule (e.g., ACC-001) checks and how to fix it |

---

### Option 3: Use with Cursor

Copy the rules file into your project:
```bash
cp cadence-guard/rules/cadence-guard.mdc /path/to/your/project/
```

Cursor auto-detects `.mdc` files and applies the rules when generating or reviewing Cadence code. The rules cover both security and code quality.

You can also add the MCP server to Cursor's MCP settings for scanner access.

---

### Option 4: Use with Any LLM (ChatGPT, Gemini, etc.)

1. Open `rules/cadence-guard-rules.md`
2. Copy the entire contents
3. Paste it into your LLM conversation as context (system prompt or first message)
4. Ask it to review your Cadence contracts

Example prompt:
> "Using the Cadence Guard rules I provided, review this contract for security issues and code quality: [paste contract]"

---

### Option 5: Manual Audit (No AI)

The checklist works standalone — no AI tools needed:

1. Run the scanner: `go run scanner/cadence_audit.go ./contracts/`
2. Open `checklist/security-checklist.md` in any text editor
3. Work through each section, checking items off as you go
4. Document findings using `templates/finding-template.md`

---

### MCP Server Details

The MCP (Model Context Protocol) server lets AI tools use Cadence Guard as a tool rather than just context. It runs **locally on your machine** as a subprocess — no cloud hosting, no API keys, no external services.

**Requirements:** Python 3.10+ and the `mcp` package.

```bash
# Install the MCP dependency
pip install mcp

# Test that it works (should start and wait for stdio input)
python mcp/server.py
```

**How MCP works:** When you configure an AI tool (Claude Code, Cursor, etc.) to use the MCP server, the tool spawns `python mcp/server.py` as a local subprocess. The AI communicates with it over stdio. The server exposes the scanner and checklist as callable tools. Everything runs on your machine.

**Configure for Claude Code:**
```json
{
  "mcpServers": {
    "cadence-guard": {
      "command": "python",
      "args": ["/absolute/path/to/cadence-guard/mcp/server.py"]
    }
  }
}
```

**Configure for Cursor:**
Add to Cursor's MCP settings (Settings → MCP Servers):
- Name: `cadence-guard`
- Command: `python /absolute/path/to/cadence-guard/mcp/server.py`

---

## Repository Structure

```
cadence-guard/
├── README.md                          ← You are here
├── CLAUDE.md                          ← Claude Code AI rules (auto-loaded)
├── LICENSE                            ← Apache 2.0
├── CONTRIBUTING.md                    ← How to contribute
├── ACKNOWLEDGMENTS.md                 ← Credits and attribution
├── CONTRIBUTORS.md                    ← Project contributors
│
├── scanner/
│   └── cadence_audit.go               ← Static security scanner (21 rules)
│
├── checklist/
│   └── security-checklist.md          ← Manual audit checklist (10 sections, 50+ items)
│
├── mcp/
│   ├── server.py                      ← MCP server (local, no hosting needed)
│   └── requirements.txt               ← Python dependencies (just: mcp)
│
├── examples/
│   ├── vulnerable.cdc                 ← Example contract with security issues
│   └── remediated.cdc                 ← Same contract with all issues fixed
│
├── templates/
│   └── finding-template.md            ← Finding documentation template
│
└── rules/
    ├── cadence-guard.mdc              ← Cursor IDE rules
    └── cadence-guard-rules.md         ← Generic LLM rules (any AI tool)
```

---

## Acknowledgments

This project aggregates and builds on security knowledge from across the Flow ecosystem:

- **[Flow Engineering Team](https://flow.com/)** — The Cadence Smart Contract Audit Prompt informed several checklist items around code quality, DeFi checks, and Cadence idioms
- **[onflow/cadence-rules](https://github.com/onflow/cadence-rules)** — AI-friendly Cadence development rules for Cursor, covering language fundamentals, security patterns, and best practices. Cadence Guard complements that work by focusing on security auditing. Some patterns and conventions referenced here align with their rule set
- **[Cadence Documentation](https://cadence-lang.org/docs/)** — Security best practices, design patterns, anti-patterns, and project development tips from the official docs form the foundation of this framework
- **[Flow Bug Bounty Program](https://flow.com/flow-responsible-disclosure)** — Severity classification and real-world vulnerability patterns

See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for full details.

---

## Contributing

We welcome contributions from the Flow community:

- **Add scanner rules** — new regex patterns for security anti-patterns
- **Improve the checklist** — new items, better tests, additional sections
- **Add AI rules** — keep rules consistent across Claude/Cursor/generic formats
- **Report false positives** — help us reduce noise
- **Share vulnerability patterns** — if you've found a pattern not covered, submit it

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
