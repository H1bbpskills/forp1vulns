# Fiat-Shamir Hash Truncation in MtA Range ZKP

**Severity:** Medium (CVSS 3.1: AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N — 5.3)
**Class:** CWE-131 — Incorrect Calculation of Buffer Size
**Target:** `src/common/cosigner/mta.cpp`, line 130
**Status:** Confirmed

---

## Summary

In `src/common/cosigner/mta.cpp` line 130, the function `generate_mta_range_zkp_seed` hashes the Paillier ciphertext `proof.A` (~512 bytes) using the byte-length of `proof.S` (~128 bytes) instead of `proof.A`'s own byte-length. This causes only 128 out of ~512 bytes of the ciphertext to be included in the Fiat-Shamir challenge derivation. 75% of the ciphertext value is unbound by the challenge, breaking the formal soundness proof of the MtA range zero-knowledge proof.

---

## Description

The Multiplicative-to-Additive (MtA) protocol is the core building block of threshold ECDSA signing in the CMP protocol (IACR ePrint 2020/492). During MtA, each party proves in zero knowledge that their Paillier-encrypted value lies within a valid range. The proof's soundness depends on the Fiat-Shamir transform binding the challenge `e` to every element of the proof transcript.

The function `generate_mta_range_zkp_seed` (line 115) computes a SHA-256 seed for Fiat-Shamir challenge derivation. At line 130, it hashes `proof.A` — a Paillier ciphertext in Z_{N²} — but passes `BN_num_bytes(proof.S)` as the length argument instead of `BN_num_bytes(proof.A)`:

```cpp
// mta.cpp lines 128-130 (BUGGY)
std::vector<uint8_t> n(BN_num_bytes(proof.A));       // allocates ~512 bytes
BN_bn2bin(proof.A, n.data());                         // writes all ~512 bytes of A
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // hashes only ~128 bytes (S's size)
```

The correct version exists in the same file at line 104 (`generate_mta_range_zkp_extended_seed`):

```cpp
// mta.cpp line 104 (CORRECT)
hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A"); // hashes all 512 bytes
```

Key sizes from `cmp_setup_service.cpp` lines 24-25:
- **Paillier:** 2048-bit key → N = 256 bytes → N² = 512 bytes → `proof.A` ≈ **512 bytes**
- **Ring-Pedersen:** 1024-bit key → N_rp = 128 bytes → `proof.S` ≈ **128 bytes**

Serialization confirms: `proof.A` is `paillier_pub_n_size * 2` = 512 bytes (line 191), `proof.S` is `ring_pedersen_n_size` = 128 bytes (line 213).

**Result:** Only 128 of 512 bytes of A enter the Fiat-Shamir hash. The upper 384 bytes (3072 bits) are completely unbound.

**Reachability:** The buggy path is used in two ways:
1. When `version < MPC_EXTENDED_MTA (11)` — lines 552-558 (prover) and 988-994 (verifier)
2. Hardcoded `use_extended_seed=0` in Rddh and log proofs at lines 658, 661, 669, 672 — **always active regardless of protocol version**

---

## Steps to Reproduce

### Prerequisites

- Linux system with `g++` and `libssl-dev` (OpenSSL)
- No library build required — the PoC is standalone

### Step 1: Clone the repos

```bash
git clone https://github.com/fireblocks/mpc-lib.git
git clone https://github.com/H1bbpskills/forp1vulns.git
```

### Step 2: Verify the bug in source code

```bash
sed -n '128,130p' mpc-lib/src/common/cosigner/mta.cpp
```

Output:
```cpp
    std::vector<uint8_t> n(BN_num_bytes(proof.A));
    BN_bn2bin(proof.A, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // right size of S is ensured during serialization
```

The third argument to `SHA256_Update` should be `BN_num_bytes(proof.A)` but uses `BN_num_bytes(proof.S)`.

### Step 3: Verify the sizes are different

```bash
grep -n 'PAILLIER_KEY_SIZE\|RING_PEDERSEN_KEY_SIZE' mpc-lib/src/common/cosigner/cmp_setup_service.cpp | head -2
```

Output:
```
24:static const uint32_t PAILLIER_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 8; // 2048 bits
25:static const uint32_t RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4; // 1024 bits
```

- `sizeof(elliptic_curve256_scalar_t)` = 32 bytes
- Paillier: 32 × 8 × 8 = 2048 bits → N² ≈ 512 bytes (proof.A)
- Ring-Pedersen: 32 × 8 × 4 = 1024 bits → N_rp ≈ 128 bytes (proof.S)

### Step 4: Verify hardcoded reachable paths

```bash
grep -n 'use_extended_seed.*0' mpc-lib/src/common/cosigner/mta.cpp | head -4
```

Output:
```
658: ... /*use_extended_seed=*/0 ...
661: ... /*use_extended_seed=*/0 ...
669: ... /*use_extended_seed=*/0 ...
672: ... /*use_extended_seed=*/0 ...
```

These are active in every protocol version — the buggy seed path is always reachable.

### Step 5: Compile and run the PoC

```bash
g++ -std=c++17 -w -o poc_test forp1vulns/poc/fs_truncation_poc.cpp -lssl -lcrypto
./poc_test
```

**Expected output:**

```
=== Fiat-Shamir Hash Truncation PoC ===

Step 1: Verify sizes match the library's defaults
  BN_num_bytes(A) = 512  (expected ~512)
  BN_num_bytes(S) = 128  (expected ~128)
  Bytes of A actually hashed (buggy) = 128
  Bytes of A SKIPPED          = 384 (75%)

Step 2: Modify byte 200 of A (OUTSIDE hashed range)
  Seed with original A: <hex>
  Seed with modified A: <hex>  ← IDENTICAL to above
  RESULT: IDENTICAL — byte 200 of A is NOT in the hash!
  >>> BUG CONFIRMED: modifying A does not change the FS challenge <<<

Step 3: Modify byte 50 of A (INSIDE hashed range)
  Seed with original A: <hex>
  Seed with byte-50  A: <hex>  ← DIFFERENT
  RESULT: Different — byte 50 IS in the hash (as expected)

Step 4: Fixed version (using BN_num_bytes(A) as length)
  Fixed seed original A: <hex>
  Fixed seed modified A: <hex>  ← DIFFERENT
  RESULT: Different — fix correctly includes all bytes of A

=== SUMMARY ===
Buggy hash: modifying byte 200 of A produces same seed?  YES (BUG)
Buggy hash: modifying byte 50 of A produces diff seed?   YES (only first 128 bytes matter)
Fixed hash: modifying byte 200 of A produces diff seed?  YES (fix works)

>>> ALL CHECKS PASSED: Vulnerability confirmed <<<
  - 384 of 512 bytes of A are excluded from the FS challenge
  - A malicious prover has 2^3072 collision classes for A
  - The one-line fix (use BN_num_bytes(proof.A)) resolves it
```

**What the PoC proves:**
- Two different Paillier ciphertexts A₁ and A₂ (differing at byte 200) produce the **same** SHA-256 Fiat-Shamir seed
- A modification within the first 128 bytes **does** change the seed — confirming that only bytes 0–127 are hashed
- The one-line fix resolves it — all bytes of A are included

---

## Security Impact

### What breaks (formal)

The Fiat-Shamir transform's security reduction requires the challenge `e` to be a deterministic function of the **entire** proof transcript. By omitting 75% of the Paillier ciphertext A, the security proof from the CMP paper (IACR ePrint 2020/492, Section 4.2) no longer holds. The MtA range proof cannot be formally proven sound.

### What breaks (practical)

A malicious cosigner gains a search space of ~2^3072 (from the 384 unbound bytes of A) to find favorable proof parameters. The attack works as follows:

**Phase 1 — Per signing session:**
1. The malicious cosigner participates in the MtA sub-protocol
2. They must produce a range proof that their encrypted value is in the valid range
3. They choose a value `x` that is **slightly** outside the intended range
4. They compute `A = Enc(beta) * K^alpha mod N²` for many `(alpha, beta, r)` triples
5. All triples whose `A` values share the same first 128 bytes produce the **same** challenge `e`
6. Among the 2^3072 collision classes, they search for a triple where `z1 = alpha + e*x` still passes the verifier's independent range check at line 975 (`z1 ≤ 96 bytes`)

**Phase 2 — Multi-session accumulation:**
7. Repeat across many signing sessions, each with a slightly biased `x`
8. The biased MtA shares translate to biased ECDSA nonces
9. After enough sessions (estimated 2^20 to 2^40), apply a lattice-based attack (Howgrave-Graham & Smart) to recover the honest party's ECDSA private key share

### What does NOT break

The independent range check on `z1` at line 975 prevents a single-shot forgery where a grossly out-of-range value is used. The attack requires many signing sessions to accumulate sufficient statistical bias.

### SECURITY-MODEL.md scope

This is a library-level implementation bug in the `crypto/cosigner` layer (§1 responsibility). It is not an integrator-contract issue. Both prover and verifier code use the same buggy hash function. It violates §1.2.1 (Long-term key secrecy) over multiple protocol executions.

---

## Mitigation

### Immediate fix (one line)

In `src/common/cosigner/mta.cpp`, line 130, change:

```cpp
// BEFORE (buggy):
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));

// AFTER (fixed):
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.A));
```

### Recommended fix — deprecate the non-extended seed path

1. Change all hardcoded `use_extended_seed=0` to `use_extended_seed=1`:
   - `mta.cpp` lines 658, 661, 669, 672
   - `cmp_ecdsa_online_signing_service.cpp` line 200
   - `cmp_ecdsa_signing_service.cpp` line 176
2. Remove `generate_mta_range_zkp_seed` entirely
3. Enforce minimum protocol version `MPC_EXTENDED_MTA` (11)

**Note:** Changing the seed function changes the Fiat-Shamir challenge. Proofs generated with the old function will not verify with the new one. This requires a coordinated upgrade across all cosigner nodes.

---

## References

- CWE-131: https://cwe.mitre.org/data/definitions/131.html
- CMP Protocol: IACR ePrint 2020/492, Section 4.2 (MtA range proof)
- Fiat-Shamir soundness: challenge must bind to ALL proof elements
- Howgrave-Graham & Smart: Lattice attack on biased ECDSA nonces
- Bleichenbacher: Statistical bias exploitation in DSA/ECDSA
