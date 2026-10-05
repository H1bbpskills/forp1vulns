# PoC Reproduction: Cosigner Bypass via Bid Edit + Take Bid Settlement

## Overview

This PoC extends the original finding by completing the full attack chain:

1. **Bid creation** — buyer places a 5 SOL bid with a cosigner
2. **Bid edit** — buyer changes amount to 1 SOL WITHOUT cosigner approval
3. **Take bid** — seller accepts; trade settles at 1 SOL with the stale cosigner key

This proves fund-level impact: the manipulated bid terms survive into a completed transfer.

## Prerequisites

- Node.js >= 18
- pnpm
- Rust / Solana CLI (for building the on-chain program)
- Anchor CLI

## Setup & Run

### Option A: Run inside the marketplace repo (recommended)

```bash
# 1. Clone the marketplace repo
git clone https://github.com/tensor-foundation/marketplace.git
cd marketplace

# 2. Install dependencies
pnpm install

# 3. Build the on-chain program
pnpm programs:build

# 4. Copy the PoC test file into the test directory
cp /path/to/bidEditTakeBid.test.ts clients/js/test/mpl_core/bidEditTakeBid.test.ts

# 5. Run ONLY the PoC tests
pnpm clients:js:test -- --match "PoC*"
```

### Option B: Run individual tests

```bash
cd marketplace/clients/js

# Run the amount manipulation test
npx ava test/mpl_core/bidEditTakeBid.test.ts --match "PoC: cosigner bypass*amount*"

# Run the broker redirection test
npx ava test/mpl_core/bidEditTakeBid.test.ts --match "PoC: cosigner bypass*broker*"
```

## What to Expect

### Test 1: Amount Manipulation

```
Step 1: Creating MPL Core asset owned by seller...
Step 2: Buyer places bid for 5 SOL with cosigner...
  Bid created at <PDA>
  Amount: 5 SOL
  Cosigner: <cosigner_pubkey>
Step 3: Buyer edits bid to 1 SOL WITHOUT cosigner...
  Amount after edit: 1 SOL
  Cosigner after edit: <cosigner_pubkey> (unchanged!)
  >> VULNERABILITY: amount modified without cosigner approval
Step 4: Seller takes the bid with original cosigner — settles at manipulated price...
Step 5: Verifying attack outcome...

=== ATTACK SUMMARY ===
  Original bid:     5 SOL
  Manipulated bid:  1 SOL
  Seller received:  ~0.87 SOL  (1 SOL minus fees)
  Buyer saved:      ~4 SOL
  NFT transferred:  YES
  Cosigner bypass:  YES (stale key accepted by take_bid)
======================
```

### Test 2: Maker Broker Fee Theft

```
=== BROKER REDIRECTION RESULT ===
  Attacker broker received:    <non-zero> lamports
  Legitimate broker received:  0 lamports
=================================
```

## Root Cause (for reference)

**File:** `program/src/instructions/bid.rs`

The `bid` instruction's edit branch (when `bid_state.target_id != Pubkey::default()`)
only enforces immutability on `target`, `target_id`, `field`, and `field_id`.

The `cosigner` field is set during initialization only:

```rust
// INIT branch — cosigner is set
if bid_state.target_id == Pubkey::default() {
    bid_state.target = target.clone();
    bid_state.target_id = target_id;
    bid_state.field.clone_from(&field);
    bid_state.field_id = field_id;
    match &ctx.accounts.cosigner {
        Some(cosigner) if cosigner.key() != ctx.accounts.owner.key() => {
            bid_state.cosigner = cosigner.key();
        }
        _ => (),
    }
} else {
    // EDIT branch — only checks target/target_id/field/field_id
    // cosigner is NOT checked here
}
```

Meanwhile, `amount`, `quantity`, `private_taker`, `maker_broker` are overwritten
unconditionally on every call (lines above the branch).

In `take_bid`, the cosigner is validated against `bid_state.cosigner`:

```rust
if bid_state.cosigner != Pubkey::default() {
    let signer = self.cosigner.as_ref().ok_or(TcompError::BadCosigner)?;
    require!(bid_state.cosigner == *signer.key, TcompError::BadCosigner);
}
```

This check passes because the cosigner field was never modified — only the
economic terms were changed without the cosigner's knowledge.
