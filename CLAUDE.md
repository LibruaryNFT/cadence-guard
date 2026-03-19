# Cadence Guard

You are assisting with a Cadence smart contract security audit using the Cadence Guard framework.

## What This Is

Cadence Guard is a community-driven security and code quality framework for Cadence smart contracts on the Flow blockchain. It provides a static scanner, a manual audit checklist, and finding templates.

## Quick Start

1. **Run the scanner first** to catch automated patterns:
   ```
   go run scanner/cadence_audit.go <path-to-contracts>
   ```
2. **Walk the checklist** in `checklist/security-checklist.md` for manual review
3. **Document findings** using `templates/finding-template.md`

## Scanner Rules (21 rules, 8 categories)

| Category | Rules | What It Catches |
|----------|-------|-----------------|
| ACC (Access Control) | ACC-001–004 | `access(all)` on sensitive functions, deprecated `pub`, unprotected admin functions |
| RES (Resource Safety) | RES-001–003 | Destroy without balance zeroing, force-unwrap moves, missing `view` annotations |
| TOK (Token/Vault) | TOK-001–004 | Missing type guards on deposits, unchecked minting/burning, division-before-multiplication |
| STO (Storage) | STO-001–002 | String interpolation in storage paths, unchecked borrows |
| INP (Input Validation) | INP-001–003 | Public functions without pre-conditions, nil-check+force-unwrap, unbounded loops |
| CAP (Capabilities) | CAP-001–002 | Capability publishing review, interface-only restriction (not secure in Cadence 1.0) |
| RND (Randomness) | RND-001 | `revertibleRandom` without commit-reveal |
| EVM (Cross-VM) | EVM-001 | Cross-VM calls needing atomicity/precision/reentrancy review |

## Checklist Sections (10 sections, 50+ items)

0. Pre-Audit Context
1. Access Control & Entitlements
2. Resource Safety
3. Token / Vault Operations
4. Storage Operations
5. Input Validation
6. Contract Update Safety
7. Randomness & Commit-Reveal
8. Resilience & Emergency Patterns
9. DeFi-Specific Checks
10. Cross-VM / EVM Bridge

## Key Cadence 1.0 Security Facts

- **Entitlements are the security boundary**, NOT interface restriction
- `canBorrow()` intentionally allows concrete type coercion
- Standard contracts publish `&ConcreteType` with entitlements, not `&{Interface}`
- Contract update validator checks fields/kinds but NOT function signatures
- All number operations have overflow/underflow checks (panics on overflow)
- Contract removal is BLOCKED on mainnet (emulator allows it)

## Severity Guide

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct loss of funds, resource duplication, unauthorized minting. External attacker, no special access. Mainnet-viable. |
| **High** | Significant state corruption, entitlement bypass, DoS of critical functions. Mainnet-viable. |
| **Medium** | Logic errors with limited impact, griefing, information disclosure. May require specific conditions. |
| **Low** | Minor: missing validation with no exploitable impact, unnecessary capabilities, code quality. |
| **Info** | Best practice deviations, defense-in-depth suggestions. Not directly exploitable. |

## References

- [Cadence Security Best Practices](https://cadence-lang.org/docs/security-best-practices)
- [Cadence Design Patterns](https://cadence-lang.org/docs/design-patterns)
- [Cadence Anti-Patterns](https://cadence-lang.org/docs/anti-patterns)
- [Cadence Linter](https://developers.flow.com/build/tools/flow-cli/lint)
