# Contributing to Cadence Guard

We welcome contributions from the Flow community. Here's how you can help.

## Ways to Contribute

### Add Scanner Rules
The static analyzer in `scanner/cadence_audit.go` uses regex-based pattern matching. To add a new rule:

1. Add a `Rule` struct to the `rules` slice with:
   - `ID`: Category prefix + number (e.g., `ACC-005`, `TOK-005`)
   - `Severity`: `critical`, `high`, `medium`, `low`, or `info`
   - `Pattern`: A regex matching the vulnerable pattern
   - `Description`: What the issue is and why it matters
   - `MitigationPattern` (optional): A regex for nearby code that makes the flagged pattern safe
   - `MitigationWindow` (optional): How many lines before/after to check for mitigation

2. Test against real contracts to verify it catches real issues without excessive false positives.

### Improve the Checklist
The security checklist in `checklist/security-checklist.md` is the manual audit walkthrough. To add an item:

1. Place it in the correct section (or propose a new section)
2. Include a **bold title**, a description of what to check, and a *Test* line describing how to verify it
3. If the check can be automated, consider also adding a scanner rule

### Add AI Rules
We support multiple AI tool formats in `rules/`. To add or improve rules:

- `rules/CLAUDE.md` — Claude Code format
- `rules/cadence-guard.mdc` — Cursor format
- `rules/cadence-guard-rules.md` — Generic markdown for any LLM

Keep rules consistent across formats. The content should be the same; only the format differs.

### Report False Positives
If the scanner flags something that isn't actually a problem, open an issue with:
- The scanner rule ID (e.g., `ACC-001`)
- The code that was flagged
- Why it's a false positive

### Share Vulnerability Patterns
If you've discovered a Cadence vulnerability pattern that isn't covered, open an issue or PR describing:
- The vulnerability class
- A minimal code example
- Why it's dangerous
- How to fix it

## Code of Conduct

Be respectful, constructive, and focused on improving Cadence security for everyone.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
