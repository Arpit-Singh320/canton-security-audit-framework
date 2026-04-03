# The Canton/Daml Top 10 Most Critical Smart Contract Security Risks

This document outlines the most critical security risks for Daml smart contracts running on the Canton Network, inspired by the [OWASP Top 10](https://owasp.org/www-project-top-ten/). It serves as a guide for developers, auditors, and architects to build secure and robust decentralized applications.

---

### DV-001: Improper Signatory and Observer Management

**Description:** The most fundamental security risk in Daml is incorrectly assigning parties to the `signatory` and `observer` fields. A signatory must authorize the creation and archival of a contract. An observer can see the contract and all its future actions. Accidentally granting signatory rights to the wrong party can lead to unauthorized archival or prevention of archival. Granting observer rights leaks sensitive data to unauthorized parties.

**Vulnerable Code Example:**
```daml
template Iou
  with
    issuer: Party
    owner: Party
    auditor: Party -- The auditor should only see the Iou, not control it.
    amount: Decimal
    currency: Text
  where
    signatory issuer, owner, auditor -- BAD: Auditor can prevent archival.
```

**Secure Code Example:**
```daml
template Iou
  with
    issuer: Party
    owner: Party
    auditor: Party
    amount: Decimal
    currency: Text
  where
    signatory issuer, owner
    observer auditor -- GOOD: Auditor has read-only access.
```

**Mitigation:**
- Apply the principle of least privilege. Only grant signatory rights to parties who must have authoritative control over the contract's lifecycle.
- Use `observer` for all parties who need read-only access.
- Regularly review signatory and observer lists, especially in complex multi-party contracts.

---

### DV-002: Choice Controller Misconfiguration

**Description:** A choice's `controller` determines who can exercise it. If the controller set is too broad or incorrect, a party can trigger state transitions they are not authorized for, potentially leading to asset theft, fraudulent state changes, or locking up a workflow.

**Vulnerable Code Example:**
```daml
template CashAsset
  with
    issuer: Party
    owner: Party
    amount: Decimal
  where
    signatory issuer, owner

    choice Transfer : ContractId CashAsset
      with
        newOwner: Party
      controller issuer, owner -- BAD: The issuer can unilaterally transfer the owner's cash.
      do
        create this with owner = newOwner
```

**Secure Code Example:**
```daml
template CashAsset
  with
    issuer: Party
    owner: Party
    amount: Decimal
  where
    signatory issuer, owner

    choice Transfer : ContractId CashAsset
      with
        newOwner: Party
      controller owner -- GOOD: Only the current owner can initiate a transfer.
      do
        create this with owner = newOwner
```

**Mitigation:**
- Always restrict the `controller` to the party (or parties) who logically own the action.
- For multi-party actions, list all required controllers explicitly.
- Use `ensure` checks inside the choice body for an additional layer of authorization logic if needed.

---

### DV-003: Missing Authorization Checks in Choices

**Description:** Even with correctly configured controllers, complex choices might require additional authorization checks within the `do` block. Failing to add `ensure` or `assert` statements can create loopholes where a valid controller can perform an invalid action. This is common in multi-step proposal/acceptance workflows.

**Vulnerable Code Example:**
```daml
template SaleProposal
  with
    seller: Party
    buyer: Party
    price: Decimal
  where
    signatory seller, buyer

    choice Accept : ContractId SaleAgreement
      with
        -- A malicious seller could try to accept on behalf of the buyer.
        -- While the controller is correct, the logic doesn't verify the actor.
        actor: Party
      controller seller, buyer
      do
        -- BAD: No check to ensure the 'actor' is the actual buyer.
        create SaleAgreement with seller, buyer, price
```

**Secure Code Example:**
```daml
template SaleProposal
  with
    seller: Party
    buyer: Party
    price: Decimal
  where
    signatory seller, buyer

    choice Accept : ContractId SaleAgreement
      with
        -- No 'actor' field needed, the controller *is* the actor.
      controller buyer -- GOOD: Controller is restricted to only the buyer.
      do
        -- GOOD: An explicit check provides defense-in-depth.
        ensure (getParty signatory == buyer)
        create SaleAgreement with seller, buyer, price
```

**Mitigation:**
- Never trust input parameters to a choice without validation.
- Use `ensure` to validate that the party exercising the choice (retrieved via `getParty signatory`) matches the expected role (e.g., `buyer`, `approver`).

---

### DV-004: Inadequate Archival and State Management

**Description:** Daml workflows often involve archiving one contract and creating a new one to represent a state change. If the old contract is not archived, it leads to a "zombie contract" state. This can cause confusion, duplicate actions, and incorrect queries, as multiple contracts may appear to represent the current state.

**Vulnerable Code Example:**
```daml
template Document
  with
    owner: Party
    content: Text
    version: Int
  where
    signatory owner

    choice UpdateContent : ContractId Document
      with
        newContent: Text
      controller owner
      do
        -- BAD: Creates a new version but leaves the old one on the ledger.
        create this with content = newContent, version = version + 1
```

**Secure Code Example:**
```daml
template Document
  with
    owner: Party
    content: Text
    version: Int
  where
    signatory owner

    choice UpdateContent : ContractId Document
      with
        newContent: Text
      controller owner
      do
        -- GOOD: Archives the current contract before creating the new one.
        archive self
        create this with content = newContent, version = version + 1
```

**Mitigation:**
- In any choice that creates a successor contract, the first action should almost always be `archive self`.
- Design workflows as state machines where each transition explicitly archives the previous state.

---

### DV-005: Time-Based Vulnerabilities

**Description:** Relying on `getTime` for critical business logic is dangerous. The time is provided by the submitting party and is only validated to be within a tolerance window by the Canton domain. An attacker can manipulate this time (within limits) to win a race condition, cause an option to expire prematurely, or otherwise exploit time-sensitive logic.

**Vulnerable Code Example:**
```daml
template Auction
  with
    item: Text
    seller: Party
    highestBidder: Party
    highestBid: Decimal
    deadline: Time
  where
    signatory seller

    choice CloseAuction : ()
      controller seller
      do
        now <- getTime
        -- BAD: A seller can submit this just after the deadline
        -- but set the transaction time to be just before.
        assert (now >= deadline)
        -- ... logic to award item to highestBidder
```

**Secure Code Example:**
```daml
-- Using an external "Oracle" pattern is safer.
template TimeOracle
  with
    operator: Party
    currentTime: Time
  where
    signatory operator

    choice AdvanceTime : ContractId TimeOracle
      with newTime: Time
      controller operator
      do create this with currentTime = newTime

-- The choice now consumes a fact from a trusted time source.
choice CloseAuction : ()
  with
    oracleCid: ContractId TimeOracle
  controller seller
  do
    oracle <- fetch oracleCid
    -- GOOD: Time is based on a trusted external contract, not the submitter's clock.
    assert (oracle.currentTime >= deadline)
    -- ... logic to award item
```

**Mitigation:**
- Avoid using `getTime` for business-critical deadlines or sequencing.
- Use an external, trusted Time Oracle contract operated by a neutral or agreed-upon party.
- For simpler cases, use a "heartbeat" choice that must be exercised by a party to advance the state, rather than relying on automatic time progression.

---

### DV-006: Data Disclosure Through Transitive Dependencies

**Description:** In Daml, if you can see a contract, you can see all contracts it was created from within the same transaction. This means if Contract B is created in a choice on Contract A, any observer of Contract B also implicitly becomes an observer of Contract A for that transaction. This can leak information from Contract A that was not intended for the observers of Contract B.

**Vulnerable Code Example:**
```daml
template PrivateAgreement
  with
    partyA: Party
    partyB: Party
    secretValue: Text -- Should only be seen by A and B
  where
    signatory partyA, partyB

    choice CreatePublicRecord : ContractId PublicRecord
      with
        auditor: Party -- Can see the PublicRecord
      controller partyA
      do
        -- BAD: When the auditor fetches PublicRecord, they can also see
        -- the PrivateAgreement that created it in the transaction view.
        create PublicRecord with owner = partyA, auditor
```

**Secure Code Example:**
```daml
-- Split the workflow into two separate transactions.

-- Step 1: Propose the creation
template PublicRecordProposal
  with
    proposer: Party
    auditor: Party
  where
    signatory proposer, auditor
    choice Accept: ContractId PublicRecord
      controller proposer
      do create PublicRecord with owner = proposer, auditor

-- In a script or off-ledger application:
-- 1. Create PrivateAgreement between partyA and partyB.
-- 2. In a SEPARATE transaction, partyA creates a PublicRecordProposal.
-- This decouples the contracts, breaking the visibility chain.
```

**Mitigation:**
- Decouple sensitive and non-sensitive data creation into separate transactions.
- Use proposal/acceptance patterns to break the transaction chain.
- Carefully model which parties are observers on contracts created within choices.

---

### DV-007: Unchecked Input in `create` and `exercise`

**Description:** Daml's type system provides strong guarantees, but it does not validate the semantic content of data. A choice might accept a `Text` field for an email address or a `Decimal` for a price. Without `ensure` checks, a user could submit nonsensical data (e.g., a negative price, an invalid email format) that breaks off-ledger systems or downstream logic.

**Vulnerable Code Example:**
```daml
template ItemForSale
  with
    seller: Party
    item: Text
    price: Decimal
  where
    signatory seller

    choice UpdatePrice : ContractId ItemForSale
      with
        newPrice: Decimal
      controller seller
      do
        -- BAD: Allows setting a negative or zero price.
        create this with price = newPrice
```

**Secure Code Example:**
```daml
template ItemForSale
  with
    seller: Party
    item: Text
    price: Decimal
  where
    signatory seller
    ensure price > 0.0

    choice UpdatePrice : ContractId ItemForSale
      with
        newPrice: Decimal
      controller seller
      do
        -- GOOD: Validates the input before creating the new contract.
        ensure newPrice > 0.0
        create this with price = newPrice
```

**Mitigation:**
- Add `ensure` conditions to both the `where` block of the template (for creation) and the `do` block of choices (for updates).
- Validate all inputs for logical consistency (e.g., prices must be positive, quantities must be non-negative, dates must be in the future).

---

### DV-008: Lack of Contract Upgrade Path

**Description:** Smart contract logic may need to be updated to fix bugs or add features. Daml template versions are static; old contracts do not automatically migrate to new template versions. If no upgrade path is designed into the workflow, active contracts can be permanently stuck on an old, buggy, or insecure version.

**Vulnerable Code Example:**
A system with no mechanism to move data from a `MyAsset_v1` contract to a `MyAsset_v2` contract.

**Secure Code Example:**
```daml
-- In MyAsset_v1.daml
template MyAsset_v1
  with
    owner: Party
    data: Text
  where
    signatory owner
    choice UpgradeToV2 : ContractId MyAsset_v2
      controller owner
      do
        -- Logic to create the new version of the contract
        create MyAsset_v2 with owner, data, newDataField = "default"
```
**Mitigation:**
- For long-lived contracts, include an "upgrade" or "migrate" choice from the beginning.
- This choice should be controlled by the appropriate authority (e.g., the signatories or a designated operator).
- The choice should archive the old contract and create a new contract instance using the updated template, carrying over all relevant data.

---

### DV-009: Denial of Service via Non-Consuming Choices

**Description:** Choices can be either "consuming" (they archive the contract) or "non-consuming" (they leave the contract active). A non-consuming choice that performs a read-only action or creates another independent contract can potentially be exercised an unlimited number of times. If this choice is complex or logs extensive data, it could be used to flood the ledger or bog down participant nodes.

**Vulnerable Code Example:**
```daml
template Poll
  with
    question: Text
    creator: Party
    voters: [Party]
  where
    signatory creator
    observer voters

    -- BAD: Non-consuming choice can be called repeatedly by the same voter.
    choice Vote : ()
      with
        voter: Party
        vote: Text
      controller voter
      do
        assert (elem voter voters)
        -- Imagine this logs a complex event to an off-ledger system.
        -- A malicious voter could call this thousands of times.
        return ()
```

**Secure Code Example:**
```daml
template Poll
  with
    question: Text
    creator: Party
    votersWhoHaventVoted: [Party]
  where
    signatory creator
    observer votersWhoHaventVoted

    choice Vote : ContractId Poll
      with
        vote: Text
      controller (head votersWhoHaventVoted) -- Only one party at a time.
      do
        let voter = head votersWhoHaventVoted
        -- GOOD: State is updated to remove the voter, preventing a second vote.
        archive self
        create this with votersWhoHaventVoted = tail votersWhoHaventVoted
```

**Mitigation:**
- Prefer consuming choices for actions that represent a unique event (like voting or claiming a reward).
- If a choice must be non-consuming, ensure it cannot be abused. Add state to the contract to track who has already performed the action.
- Use key assertions to prevent duplicate contract creations that could enable abuse.

---

### DV-010: Broken Atomicity with Off-Ledger Systems

**Description:** A Daml transaction is atomic: it either fully succeeds or fully fails. However, this atomicity does not extend to external, off-ledger systems. A common mistake is to exercise a choice that changes ledger state and *then* try to trigger an off-ledger action (like a fiat payment). If the off-ledger part fails, the ledger state is now inconsistent with the real world.

**Vulnerable Code Example:**
An off-ledger UI application that does the following:
1. Exercises a `Transfer` choice on a Daml asset. The transaction succeeds.
2. Tries to call a banking API to make a corresponding fiat payment. The API call fails due to a network error.
Result: The digital asset has moved, but the money has not.

**Secure Code Example:**
Use a two-phase commit or escrow pattern.

```daml
-- Phase 1: Lock the asset
template Asset
  with owner: Party; ...
  where
    choice LockForPayment : ContractId LockedAsset
      with paymentProvider: Party; ...
      controller owner
      do create LockedAsset with owner, paymentProvider, ...

-- Phase 2: The external system confirms payment and unlocks
template LockedAsset
  with owner: Party; paymentProvider: Party; ...
  where
    choice ConfirmPaymentAndUnlock : ContractId Asset
      with newOwner: Party
      controller paymentProvider -- Only the trusted payment provider can confirm.
      do create Asset with owner = newOwner, ...
```

**Mitigation:**
- Never assume off-ledger actions are atomic with on-ledger ones.
- Use multi-phase patterns (e.g., escrow, lock/commit) where the ledger state reflects the intermediate step.
- An external system or oracle is responsible for advancing the state only after confirming the off-ledger action has completed successfully.
- For failed off-ledger actions, include "revert" or "timeout" choices to return the contract to its original state.