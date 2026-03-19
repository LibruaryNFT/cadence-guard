# Cadence Guard — Security & Code Quality Rules

Use this file as a system prompt or context document when asking any LLM to review
or generate Cadence smart contracts. Copy it into your tool of choice (Claude, ChatGPT,
Gemini, etc.) or reference it as context.

For Claude Code users: use `CLAUDE.md` in the repo root instead (it's optimized for that workflow).
For Cursor users: use `rules/cadence-guard.mdc` instead.

---

## Security Rules (MUST follow)

### Access Control
- Default to `access(self)` or `access(contract)` for all declarations
- Use entitlements (`access(Withdraw)`, `access(Admin)`) for privileged operations
- NEVER use `access(all)` on: withdraw, deposit, burn, mint, transfer, destroy, admin, set, update, remove
- Interface restriction (`&{Interface}`) is NOT a security boundary in Cadence 1.0 — use entitlements
- Published capabilities must use concrete types with specific entitlements
- Prefer `access(self)` for internal functions/fields to minimize attack surface

### Resource Safety
- Resources must be explicitly moved (`<-`) or destroyed — never copied or silently lost
- Trace every `create` to its `destroy` or `move`
- `destroy` callbacks must not call external contracts or leak entitlements
- Force-unwrap move (`<-!`) on nil destroys the resource — verify nil is impossible
- Collection operations (insert/remove/append) on resource arrays/dicts must not duplicate or lose resources

### Token / Vault Operations
- `deposit()` must verify incoming vault type: `vault.getType() == Type<@X.Vault>()` or `vault.isInstance()`
- `withdraw()` must have pre-condition: `self.balance >= amount`
- Destroying a vault must handle nonzero balance (zero first, or pre-condition)
- `mint` functions must update `totalSupply` and be access-controlled
- `burn` functions must decrement `totalSupply`
- Always multiply before dividing to preserve UFix64 precision (8 decimal places), unless overflow risk
- UFix64 max value: `92233720368.54775807` — test boundary values

### Storage Operations
- No user-controlled string interpolation in storage paths — prevents path collision
- All `borrow<>` results must be nil-checked (`?? panic` or `if let`)
- Prefer `borrow` over `load`/`save` for in-place mutations (avoids unnecessary copies)
- Storage references are like symbolic links — the target can be swapped between check and use (TOCTOU)
- Public functions that write to storage must have size limits or access control

### Input Validation
- All transaction parameters must have explicit `pre {}` conditions (range, non-nil, non-empty)
- Validate string/array lengths to prevent DoS via excessive computation
- Use `if let value = opt { ... }` instead of `if opt != nil { let value = opt! ... }`
- Verify no unbounded loops over user-growable collections (pagination or size caps)
- Validate Address parameters before use in borrow/capability operations
- Check dictionary parameters for duplicate key exploitation

### Contract Update Safety
- Contract update validator checks field types but NOT function signatures — sensitive functions could be silently changed
- On mainnet, contract removal is BLOCKED (no delete+redeploy kind confusion)
- New interface default implementations apply to ALL existing resources — verify no behavioral damage
- Enum raw values cannot change; adding cases is fine, reordering is not

### Randomness
- `revertibleRandom()` requires commit-reveal with at least 1 block separation
- Seeds must not be derived from block height, timestamp, or miner-influenceable data alone
- Random consumers must not be able to abort unfavorable results (mandatory settlement)

### Resilience & Emergency
- Critical contract functionality (trading, minting, bridging) should have an admin-controlled pause switch
- Expressions in logical/comparison operators (`&&`, `||`, `>=`, `==`) should be side-effect-free
- Errors in one user's operation must not block other users or freeze contract state

### Cross-VM / EVM Bridge (when applicable)
- Cross-VM operations must be atomic (EVM failure → Cadence rollback)
- UFix64 (8 decimals) ↔ uint256 (18 decimals) bridging must not create/destroy value
- EVM callbacks must not re-enter sensitive Cadence state
- Tokens locked on one side must equal tokens minted on the other
- Custom token associations must be immutable after creation

---

## Code Quality Rules (SHOULD follow)

### Access & Purity
- Non-mutating functions should be marked `view`
- Fields that don't need external access should use `access(self)`
- Use `let` instead of `var` when the value doesn't change

### Naming & Documentation
- Use descriptive names for fields, paths, functions, and variables
- Plural names for arrays and dictionaries (e.g., `items`, `balances`)
- Use named constants instead of magic numbers (use built-in constants like `UInt128.max`)
- Comment the "why", not the "what"
- Add argument labels to functions with many parameters
- Document public functions and non-obvious logic

### Code Patterns
- Follow Checks-Effects-Interactions pattern
- Use pre-conditions for input validation, post-conditions for result verification
- Use ternary expressions to simplify simple branching
- No debug code, TODOs, or commented-out logic in critical paths
- Avoid unnecessary `load`/`save` — prefer in-place mutations via `borrow`

---

## DeFi-Specific Rules (when applicable)

- Don't mix internal accounting with actual vault balances — track deposits/withdrawals separately
- Don't use AMM spot price as an oracle — use TWAP or off-chain oracle with sanity checks
- Validate oracle data: bounds, staleness, multi-source comparison
- Don't make arbitrary external calls from token-approval-target contracts
- Check assumptions about what other contracts do and return

---

## Cadence Language Notes

- All number operations have overflow/underflow checks (panics on overflow)
- Cadence does NOT have: `defer`, if-expressions, initial field values (must use `init`)
- Fields must be initialized in `init()`, not at declaration
- Keywords cannot be used as identifiers (see Cadence docs for full list)
- Number type conversions panic if out of range: `UInt8(UInt32.max)` panics

---

## References

- Cadence Security Best Practices: https://cadence-lang.org/docs/security-best-practices
- Cadence Design Patterns: https://cadence-lang.org/docs/design-patterns
- Cadence Anti-Patterns: https://cadence-lang.org/docs/anti-patterns
- Project Development Tips: https://cadence-lang.org/docs/project-development-tips
- Flow CLI Linter: https://developers.flow.com/build/tools/flow-cli/lint
