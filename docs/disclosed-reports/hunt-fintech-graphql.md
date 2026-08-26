# hunt-fintech-graphql — Pattern Library

> Patterns and verifiable public examples behind `hunt-fintech-graphql`. Operator-grade reference covering financial mutations, transaction state races, currency rounding bypasses, and ledger manipulation.

Fintech GraphQL implementations often sit directly on top of transaction routing services, core banking interfaces, and payment processor gateways (Stripe, Adyen, Braintree). Because GraphQL consolidates operations behind a single endpoint, authorization is commonly implemented resolver-by-resolver rather than at the network boundary, creating acute risks of state-desynchronization, negative balance injection, and race condition double-spends.

---

## Cited Public Examples

### HackerOne Bounty Disclosures — GraphQL Ledger Race Conditions
- **Source:** Disclosed HackerOne vulnerability reports against cryptocurrency and fintech platforms where GraphQL mutation batching bypassed transaction locks.
- **Pattern shape:** Multiple aliased transfer or withdrawal mutations executed concurrently in a single HTTP payload against an account with insufficient balance for multiple transfers. The backend validated the balance before any transfer completed, deducting the single balance once while executing N transactions.
- **Key trick:** Alias-batching within a single GraphQL request body (`m1: withdraw(amount: 100) m2: withdraw(amount: 100)`). This bypasses per-HTTP-request rate limits and forces backend parallel resolver execution.
- **Why it matters:** Generates critical severity payouts by causing verifiable financial loss or currency inflation.

### E-Commerce & Checkout Decimal/Negative Float Injections
- **Source:** Public bug bounty disclosures on online store checkouts and payment processing mutations.
- **Pattern shape:** GraphQL mutation accepted a negative unit price or negative quantity for a line item (e.g. `quantity: -1` or `discount: -500.00`), causing the total invoice calculation to result in a negative total or zero payment required.
- **Key trick:** Probe all `Float` and `Int` input types with boundary cases (`-1`, `0`, `0.00001`, `NaN`, `1e10`).
- **Why it matters:** Complete payment bypass and unauthorized order fulfillment.

---

## Pattern Library

### 1. Alias-Batching Currency Race Probe
- **Target:** Any transfer, checkout, or discount mutation.
- **Probe:**
  ```graphql
  mutation ConcurrencyCheck {
    op1: applyDiscount(code: "SINGLE_USE_50") { total balance }
    op2: applyDiscount(code: "SINGLE_USE_50") { total balance }
    op3: applyDiscount(code: "SINGLE_USE_50") { total balance }
  }
  ```
- **Validation:** Check if discount code or voucher was applied multiple times to the cart total.

### 2. Node-ID Wallet Identifier Manipulation
- **Target:** Global node queries (`node(id: "...")`).
- **Probe:** Decode base64 node handles to discover `Wallet:ID`, `Transaction:ID`, `Invoice:ID` formats. Re-encode arbitrary user IDs to query financial history.
- **Validation:** Retrieval of other users' ledger balances, transaction history, or linked bank account numbers.
