# Cadence Guard

Community-driven security and code quality framework for [Cadence](https://cadence-lang.org/) smart contracts on the [Flow](https://flow.com/) blockchain.

**Why this exists:** Security knowledge for Cadence is scattered across docs, blog posts, audit reports, and tribal knowledge. Cadence Guard aggregates this into a single, structured, AI-friendly framework that works with the way software is built today — with AI assistants, automated scanners, and structured checklists.

**This is a community project.** Anyone can contribute rules, scanner patterns, checklist items, or improvements. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## What's Inside

### 1. Static Scanner — `scanner/cadence_audit.go`
A Go-based pattern scanner that catches common security anti-patterns in `.cdc` files. 21 rules across 8 categories. Runs in seconds, outputs text or JSON, returns exit code 1 on high/critical findings (CI-friendly).

### 2. Security Checklist — `checklist/security-checklist.md`
A 10-section, 50+ item manual audit walkthrough. Covers everything the scanner can't catch: logic bugs, architectural issues, DeFi-specific risks, and cross-VM concerns.

### 3. AI Rules — `rules/`
Structured rule files for AI-assisted development and review. Same content, multiple formats:
- **`CLAUDE.md`** — for [Claude Code](https://claude.ai) (auto-loaded from repo root)
- **`rules/cadence-guard.mdc`** — for [Cursor](https://cursor.sh) IDE
- **`rules/cadence-guard-rules.md`** — for any LLM (copy/paste into ChatGPT, Gemini, etc.)

### 4. Finding Templates — `templates/`
Standardized templates for documenting audit findings with severity, root cause, impact, PoC, and fix recommendation.

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

## Quick Start

### Run the Scanner

```bash
# Scan contracts, show all findings
go run scanner/cadence_audit.go ./contracts/

# Only high and critical findings
go run scanner/cadence_audit.go --severity high ./contracts/

# JSON output (for CI or tooling)
go run scanner/cadence_audit.go --json ./contracts/
```

**Exit codes:** `0` = no high/critical findings, `1` = high or critical findings detected.

### Use with AI Tools

**Claude Code:** Clone this repo into your project or add it as context. The `CLAUDE.md` at the root is automatically loaded.

**Cursor:** Copy `rules/cadence-guard.mdc` into your project root. Cursor auto-detects `.mdc` rule files.

**Any other LLM:** Copy the contents of `rules/cadence-guard-rules.md` into your system prompt or conversation context, then ask it to review your contracts.

### Run a Manual Audit

1. Run the scanner first for automated catches
2. Open `checklist/security-checklist.md`
3. Work through each section against your contracts
4. Document findings using `templates/finding-template.md`

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
