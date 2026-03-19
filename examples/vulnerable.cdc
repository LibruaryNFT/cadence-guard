// Example: Vulnerable Cadence contract
// This contract contains intentional security issues that Cadence Guard will flag.
// Compare with remediated.cdc to see the fixes.

access(all) contract VulnerableToken {

    access(all) var totalSupply: UFix64

    // ACC-001: Sensitive function with access(all) — should use entitlement
    access(all) resource Vault {
        access(all) var balance: UFix64

        init(balance: UFix64) {
            self.balance = balance
        }

        // ACC-001: withdraw is publicly accessible — anyone can drain the vault
        access(all) fun withdraw(amount: UFix64): @Vault {
            self.balance = self.balance - amount
            return <- create Vault(balance: amount)
        }

        // TOK-001: deposit without type guard — accepts any vault type
        access(all) fun deposit(from: @Vault) {
            self.balance = self.balance + from.balance
            destroy from
        }
    }

    // ACC-004: admin function with access(all)
    access(all) fun setTotalSupply(newSupply: UFix64) {
        self.totalSupply = newSupply
    }

    // TOK-002: mint without totalSupply tracking
    access(all) fun mint(amount: UFix64): @Vault {
        return <- create Vault(balance: amount)
    }

    // INP-001: public function without pre-conditions
    access(all) fun transfer(from: @Vault, to: &Vault, amount: UFix64) {
        let withdrawn <- from.withdraw(amount: amount)
        to.deposit(from: <- withdrawn)
        destroy from
    }

    // TOK-004: division before multiplication — precision loss
    access(all) view fun calculateShare(amount: UFix64, rate: UFix64, scale: UFix64): UFix64 {
        return amount / scale * rate  // should be: amount * rate / scale
    }

    init() {
        self.totalSupply = 0.0
    }
}
