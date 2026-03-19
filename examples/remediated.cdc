// Example: Remediated Cadence contract
// This is the fixed version of vulnerable.cdc with all security issues resolved.

access(all) contract SecureToken {

    access(all) var totalSupply: UFix64
    access(all) var paused: Bool

    // Define entitlements for privileged operations
    access(all) entitlement Withdraw
    access(all) entitlement Admin

    access(all) resource Vault {
        access(all) var balance: UFix64

        init(balance: UFix64) {
            self.balance = balance
        }

        // FIX: withdraw requires Withdraw entitlement
        access(Withdraw) fun withdraw(amount: UFix64): @Vault {
            pre {
                !SecureToken.paused: "Contract is paused"
                self.balance >= amount: "Insufficient balance"
            }
            self.balance = self.balance - amount
            return <- create Vault(balance: amount)
        }

        // FIX: deposit includes type guard
        access(all) fun deposit(from: @Vault) {
            pre {
                from.isInstance(Type<@SecureToken.Vault>()): "Wrong vault type"
            }
            self.balance = self.balance + from.balance
            destroy from
        }
    }

    // FIX: admin function uses Admin entitlement
    access(Admin) fun setTotalSupply(newSupply: UFix64) {
        self.totalSupply = newSupply
    }

    // FIX: mint is access-controlled and tracks totalSupply
    access(Admin) fun mint(amount: UFix64): @Vault {
        pre {
            amount > 0.0: "Amount must be positive"
        }
        self.totalSupply = self.totalSupply + amount
        return <- create Vault(balance: amount)
    }

    // FIX: transfer has pre-conditions validating inputs
    access(all) fun transfer(from: @Vault, to: &Vault, amount: UFix64) {
        pre {
            !self.paused: "Contract is paused"
            amount > 0.0: "Amount must be positive"
        }
        let withdrawn <- from.withdraw(amount: amount)
        to.deposit(from: <- withdrawn)
        destroy from
    }

    // FIX: multiply before dividing to preserve precision
    access(all) view fun calculateShare(amount: UFix64, rate: UFix64, scale: UFix64): UFix64 {
        return amount * rate / scale
    }

    // FIX: emergency pause mechanism
    access(Admin) fun setPaused(paused: Bool) {
        self.paused = paused
    }

    init() {
        self.totalSupply = 0.0
        self.paused = false
    }
}
