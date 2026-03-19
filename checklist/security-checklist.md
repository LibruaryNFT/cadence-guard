# Cadence Security Audit Checklist

A structured walkthrough for auditing Cadence smart contracts. Work through each section
against the target contracts. For each item, check it off and document findings using
the [finding template](../templates/finding-template.md).

Run `go run scanner/cadence_audit.go <contracts-dir>` first for automated pattern detection,
then use this checklist for the manual review that catches what automation cannot.

---

## 0. Pre-Audit Context

- [ ] Identify all resources and tokens the contracts manage
- [ ] Map entry points: public functions, published capabilities, transaction scripts
- [ ] Identify sensitive operations: withdraw, deposit, burn, mint, transfer, destroy, admin
- [ ] List external dependencies (imported contracts, token standards like FungibleToken, NonFungibleToken)
- [ ] Check what network the contracts target (mainnet constraints differ from emulator)
- [ ] Review contract update history if available (look for entitlement/field changes)

---

## 1. Access Control & Entitlements

- [ ] **No `access(all)` on sensitive functions** — withdraw, deposit, burn, mint, transfer, destroy, admin, set, update, remove must use entitlement-gated access (e.g., `access(Withdraw)`)
  - *Test*: Search for `access(all) fun` and check each match
- [ ] **Entitlement definitions are minimal** — each entitlement grants the minimum needed, no "god mode" entitlement gating everything
  - *Test*: List all `entitlement` declarations, verify each gates a specific capability
- [ ] **Entitlement mappings are sound** — mappings don't escalate (e.g., Viewer -> Owner is a bug)
  - *Test*: Review all `entitlement mapping` declarations
- [ ] **Published capabilities use correct auth** — standard pattern publishes concrete types with specific entitlements, not `&{Interface}` alone (interface restriction is NOT security in Cadence 1.0)
  - *Test*: Search for `capabilities.publish` and verify auth tags
- [ ] **No unprotected admin functions** — any function changing contract state must be entitlement-gated or restricted to contract/account access
  - *Test*: Search for functions that modify state variables, verify access modifiers
- [ ] **Prefer `access(self)` where possible** — non-sensitive internal functions/fields should use `access(self)` rather than `access(all)` to minimize exposed surface
  - *Test*: Review all `access(all)` declarations; check if any could be tightened to `access(self)` or entitlement-gated
- [ ] **Non-mutating functions marked `view`** — functions that don't modify state should be annotated `view` to enforce purity at the type level
  - *Test*: Search for functions without `view` that have no state mutations, `emit`, or resource moves
- [ ] **Contract update cannot weaken entitlements** — if upgradeable, verify that updating cannot change `access(Withdraw)` to `access(all)` (update validator does NOT check function signatures)
  - *Test*: Review if any sensitive functions could be silently changed via upgrade

---

## 2. Resource Safety

- [ ] **Resource linearity maintained** — resources cannot be copied, duplicated, or silently lost
  - *Test*: Trace every `create` to its corresponding `destroy` or `move`
- [ ] **Destroy callbacks are safe** — `destroy` event handlers don't call external contracts or leak entitlements via side effects
  - *Test*: Search for `destroy()` handlers, verify no external calls
- [ ] **No nested resource extraction without move** — accessing `resource.field` where field is a resource uses proper `<-` move semantics
  - *Test*: Search for field access on resource types
- [ ] **Optional resource handling safe** — `<-!` (force-unwrap move) on nil destroys the resource; check for unintended destruction paths
  - *Test*: Search for `<-!` and verify nil is impossible at each site
- [ ] **Collection operations preserve linearity** — insert/remove/append on resource arrays/dicts don't duplicate or lose resources
  - *Test*: Review all array/dict operations on resource collections

---

## 3. Token / Vault Operations

- [ ] **Type guards on vault deposits** — `deposit()` verifies incoming vault type matches expected type (prevents cross-token deposits)
  - *Test*: Check `deposit` functions for `vault.getType() == Type<@X.Vault>()` or `vault.isInstance(Type<@X.Vault>())`
- [ ] **Balance cannot go negative** — `withdraw()` has pre-condition `self.balance >= amount`
  - *Test*: Check all withdraw functions for balance pre-conditions
- [ ] **Burn zeroes balance before destroy** — destroying a vault with nonzero balance must be handled (zero balance first, or pre-condition preventing it)
  - *Test*: Search for `destroy` on vault types, verify `balance = 0.0` or equivalent
- [ ] **No unchecked minting** — `mint` functions are access-controlled with supply tracking
  - *Test*: Verify `mintTokens` / `createEmptyVault` have proper access and update `totalSupply`
- [ ] **Total supply consistency** — if contract tracks `totalSupply`, every mint increments and every burn decrements
  - *Test*: Trace all `totalSupply` modifications
- [ ] **No precision issues** — UFix64 has 8 decimal places; check for truncation in division/multiplication chains
  - *Test*: Review arithmetic operations, especially division followed by multiplication
- [ ] **Multiply before dividing** — always multiply before dividing to preserve precision, unless the multiplication could overflow (Cadence panics on overflow)
  - *Test*: Search for division operations (`/`) and check if a multiplication follows that could have been done first

---

## 4. Storage Operations

- [ ] **Storage paths are deterministic** — no user-controlled path components that could collide with other users' data
  - *Test*: Search for `/storage/` paths, verify no string interpolation from user input
- [ ] **Borrow type matches save type** — `account.storage.borrow<&T>()` uses the type that was `save()`d; mismatch returns nil
  - *Test*: Trace save/borrow pairs for type consistency
- [ ] **Borrow results are nil-checked** — unchecked borrow returns are potential panic sources
  - *Test*: Search for `borrow<` without `?? panic` or `if let` handling
- [ ] **No unbounded storage growth** — public functions that write to storage must have limits or be access-controlled
  - *Test*: Identify all `save()` calls in public functions, check for size limits
- [ ] **Load atomicity** — `account.storage.load<T>()` removes before returning; verify no TOCTOU issues between load and subsequent operations
  - *Test*: Review load usage patterns for race conditions
- [ ] **Storage reference TOCTOU** — storage references work like symbolic links: the stored value they point to can be swapped for another value between check and use. Verify the same value is checked and used, or that replacement is impossible between check and use
  - *Test*: Search for `storage.borrow` results used across multiple statements; check if the underlying value could be replaced between borrow and use

---

## 5. Input Validation

- [ ] **Transaction arguments validated** — all parameters have explicit pre-conditions (range checks, non-nil, non-empty)
  - *Test*: Review every `transaction(...)` parameter list and corresponding `pre {}` block
- [ ] **Fix64/UFix64 boundary values** — test with `0.0`, max values (`92233720368.54775807`), values near precision boundary
  - *Test*: Write adversarial transactions with edge-case amounts
- [ ] **String/Array length limits** — unbounded strings or arrays in transaction args can be DoS vectors or cause excessive computation
  - *Test*: Check if any function accepts arrays without length pre-conditions
- [ ] **Address validation** — addresses used in borrow/capability operations are validated
  - *Test*: Check if Address-type parameters are used directly without validation
- [ ] **Dictionary key uniqueness** — if accepting dictionaries as arguments, verify no duplicate key exploitation
  - *Test*: Review dictionary parameter usage
- [ ] **Error-induced DoS** — verify that a panic or error in one user's operation cannot block other users' operations or freeze contract state
  - *Test*: Trace error/panic paths in public functions; check if a revert leaves state consistent
- [ ] **Loop-induced DoS** — verify no unbounded loops exist that an attacker could trigger by growing a collection (e.g., iterating all NFT IDs, all dictionary keys)
  - *Test*: Search for `for` loops over arrays/dicts that grow with user input; check for pagination or size caps
- [ ] **Use `if-let` instead of nil-check + force-unwrap** — the pattern `if opt != nil { let value = opt! }` is fragile; use `if let value = opt { ... }` instead to avoid potential nil panics
  - *Test*: Search for `!= nil` followed by `!` force-unwrap within the same block

---

## 6. Contract Update Safety

- [ ] **Field type changes blocked** — the update validator checks field types; verify no workarounds via intermediate types
  - *Note*: On mainnet, the validator runs. On emulator, it can be bypassed via delete+redeploy.
- [ ] **Kind confusion impossible** — on mainnet, contract removal is BLOCKED, so delete+redeploy kind confusion is not possible
  - *Note*: This is an emulator-only attack vector
- [ ] **Interface default function safety** — new default implementations added in updates apply to ALL existing resources implementing the interface; verify no behavioral change that damages existing users
  - *Test*: Review interface definitions for default implementations
- [ ] **Enum cases stable** — enum raw values cannot change; adding cases is fine but reordering is not
  - *Test*: Review enum definitions for stability

---

## 7. Randomness & Commit-Reveal

- [ ] **Block-based randomness uses commit-reveal** — `revertibleRandom()` in the same block as the commit is manipulable; verify at least 1 block separation
  - *Test*: Search for `revertibleRandom` and trace the commit/reveal flow
- [ ] **Seed not predictable** — if custom randomness, verify seed is not derived from block height, timestamp, or other miner-influenceable data alone
  - *Test*: Review random seed sources
- [ ] **Random consumer cannot abort unfavorable results** — check for commit-reveal with mandatory settlement (consumer can't just revert if they don't like the outcome)
  - *Test*: Verify reveal transaction always settles regardless of random outcome

---

## 8. Resilience & Emergency Patterns

- [ ] **Emergency disable / pause mechanism** — critical contract functionality (trading, minting, bridging) should have an admin-controlled pause switch for incident response
  - *Test*: Check if contract has a `paused` flag or equivalent that gates sensitive operations; verify the pause function is entitlement-gated
- [ ] **Side-effect-free logical expressions** — expressions passed to logical/comparison operators (`&&`, `||`, `>=`, `==`, etc.) should not have side effects (no function calls that mutate state)
  - *Test*: Review boolean expressions in `if`/`while`/`pre`/`post` for calls that modify state or move resources

---

## 9. DeFi-Specific Checks

_(Skip if contracts have no DeFi functionality)_

- [ ] **Internal accounting matches actual balances** — don't rely on raw vault/token balance to determine earnings or shares; track deposits and withdrawals separately
  - *Test*: Compare share/reward calculations against tracked vs actual balances
- [ ] **No spot price oracle from AMM** — don't use spot price from an AMM as a price oracle; use TWAP or off-chain oracle
  - *Test*: Check if any price calculation reads from a pool's current reserves
- [ ] **Sanity checks on oracle prices** — validate oracle data with bounds, staleness checks, and multi-source comparison to prevent manipulation
  - *Test*: Review oracle consumption for min/max bounds and freshness checks
- [ ] **No arbitrary calls from token approval targets** — if your contract is a target for token approvals, do not make arbitrary external calls from user-supplied input
  - *Test*: Trace execution paths from approved-transfer functions; verify no user-controlled call targets

---

## 10. Cross-VM / EVM Bridge

_(Skip if contracts have no EVM interaction)_

- [ ] **Atomicity** — cross-VM operations (Cadence <-> EVM) must be atomic; if EVM side fails, Cadence side must rollback
  - *Test*: Review bridge transaction structure for nested transaction usage
- [ ] **Precision preservation** — FLOW token: 8 decimal places (UFix64) vs EVM 18 (uint256); verify bridging doesn't create or destroy value through truncation
  - *Test*: Calculate precision loss for edge-case amounts
- [ ] **Reentrancy** — EVM callbacks into Cadence during bridge operations must not re-enter sensitive Cadence state
  - *Test*: Review callback paths for state mutation
- [ ] **Total supply invariant** — tokens locked on one side must equal tokens minted on the other; no double-mint or double-unlock
  - *Test*: Trace lock/mint and burn/unlock pairs
- [ ] **Custom token associations immutable** — if using flow-evm-bridge for custom tokens, verify association cannot be reassigned after creation
  - *Test*: Review association creation and lookup logic
