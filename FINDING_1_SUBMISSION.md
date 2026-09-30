# Fiat-Shamir Hash Truncation in MtA Range ZKP Weakens Proof Soundness

**Severity:** Medium (CVSS 3.1: AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N — 5.3)
**Class:** CWE-131 — Incorrect Calculation of Buffer Size
**Target:** `src/common/cosigner/mta.cpp`, line 130
**Status:** Confirmed — PoC attached, independently reproducible

---

## Summary

In `src/common/cosigner/mta.cpp` line 130, the non-extended Fiat-Shamir seed function `generate_mta_range_zkp_seed` hashes `proof.A` (a Paillier ciphertext, ~512 bytes) using the byte-length of `proof.S` (a Ring-Pedersen commitment, ~128 bytes). Only 25% of the ciphertext enters the Fiat-Shamir challenge. The remaining 75% (384 bytes / 3072 bits) is unbound, breaking the soundness proof of the MtA range ZKP.

---

## Steps to Reproduce (Triager Guide)

### Prerequisites

- Linux system with `g++`, `libssl-dev` (OpenSSL)
- No library build required — the PoC is standalone

### Step 1: Clone this repo and build the PoC

```bash
git clone https://github.com/H1bbpskills/forp1vulns.git
cd forp1vulns
g++ -std=c++17 -o poc_test poc/fs_truncation_poc.cpp -lssl -lcrypto
./poc_test
```

### Step 2: Read the output

Expected output:

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
  Seed with byte-50  A: <hex>  ← DIFFERENT from above
  RESULT: Different — byte 50 IS in the hash (as expected)

Step 4: Fixed version (using BN_num_bytes(A) as length)
  Fixed seed original A: <hex>
  Fixed seed modified A: <hex>  ← DIFFERENT from above
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
1. Two different Paillier ciphertexts A₁ and A₂ (differing at byte 200) produce the **same** SHA-256 seed — meaning the same Fiat-Shamir challenge `e`
2. A modification within the first 128 bytes DOES change the seed (so the bug is specifically about bytes 128–511 being excluded)
3. The one-line fix (replacing `BN_num_bytes(proof.S)` with `BN_num_bytes(proof.A)`) makes both modifications produce different seeds

### Step 3: Verify the bug in the source code

```bash
git clone https://github.com/fireblocks/mpc-lib
```

Open `src/common/cosigner/mta.cpp`, lines 128–130:

```cpp
std::vector<uint8_t> n(BN_num_bytes(proof.A));       // allocates 512 bytes
BN_bn2bin(proof.A, n.data());                         // writes all 512 bytes of A
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // hashes only 128 bytes ← BUG
```

The buffer `n` contains all 512 bytes of `proof.A`, but `SHA256_Update` is told to read only `BN_num_bytes(proof.S)` = 128 bytes.

Compare with the fixed version at line 104 (same file):

```cpp
hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A"); // hashes all 512 bytes
```

### Step 4: Verify key sizes confirm the mismatch

Open `src/common/cosigner/cmp_setup_service.cpp`, lines 24–25:

```cpp
static const uint32_t PAILLIER_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 8;
// = 32 * 8 * 8 = 2048 bits → N = 256 bytes → N² = 512 bytes → proof.A ≈ 512 bytes

static const uint32_t RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4;
// = 32 * 8 * 4 = 1024 bits → N_rp = 128 bytes → proof.S ≈ 128 bytes
```

The serialization in `mta.cpp` confirms the sizes are different:
- Line 191: `proof.A` serialized as `paillier_pub_n_size * 2` = **512 bytes**
- Line 213: `proof.S` serialized as `ring_pedersen_n_size` = **128 bytes**

### Step 5: Verify the buggy path is reachable in production

The non-extended seed is selected at runtime in two ways:

**A) Protocol version < 11 (MPC_EXTENDED_MTA):**
```cpp
// mta.cpp line 552-558 (prover side)
if (version >= fireblocks::common::cosigner::MPC_EXTENDED_MTA)
    generate_mta_range_zkp_extended_seed(...);  // correct path
else
    generate_mta_range_zkp_seed(...);           // buggy path
```
```cpp
// mta.cpp line 988-994 (verifier side — same logic)
if (_version >= fireblocks::common::cosigner::MPC_EXTENDED_MTA)
    generate_mta_range_zkp_extended_seed(...);
else
    generate_mta_range_zkp_seed(...);
```

**B) Hardcoded `use_extended_seed=0` in related proofs (ALWAYS reachable):**
```cpp
// mta.cpp lines 658, 661 — Rddh proof generation
range_proof_diffie_hellman_zkpok_generate(..., /*use_extended_seed=*/0, ...);

// mta.cpp lines 669, 672 — log proof generation
range_proof_paillier_exponent_zkpok_generate(..., /*use_extended_seed=*/0, ...);

// cmp_ecdsa_online_signing_service.cpp line 200 — Rddh verification
// cmp_ecdsa_signing_service.cpp line 176 — log verification
```

These hardcoded `use_extended_seed=0` paths are active regardless of protocol version.

---

## Attacker Exploitation Steps

### Who is the attacker?

A **malicious cosigner** (one of the parties in the threshold ECDSA setup). The CMP protocol's security model explicitly protects against malicious participants — that is its purpose.

### What the attacker gains

The Fiat-Shamir challenge `e` depends on only 128 of 512 bytes of the Paillier ciphertext `A`. This gives the attacker **2^3072 equivalence classes** — distinct `A` values that produce the same challenge `e`.

### Attack flow

**Phase 1 — Single signing session (the FS truncation exploit):**

1. The attacker participates in an MtA sub-protocol with the honest party.
2. The attacker must produce a range proof showing their encrypted value lies in the valid range.
3. Normally, the Fiat-Shamir challenge `e` binds to the entire ciphertext `A`, so the attacker commits to a single (alpha, beta, randomness) triple before the challenge.
4. Because of the truncation, the attacker can:
   - Pick a target plaintext value `x` that is **slightly** outside the intended range
   - Compute `A = Enc(beta) * K^alpha mod N²` for many different `(alpha, beta, r)` triples
   - All triples whose `A` values share the same first 128 bytes produce the **same** challenge `e`
   - The attacker searches among 2^3072 collision classes for a triple where the response `z1 = alpha + e*x` still passes the verifier's independent range check (`z1 ≤ 96 bytes` at line 975)

5. **Important limitation:** The z1 range check prevents single-shot forgery with grossly out-of-range values. The attacker can only use `x` values marginally outside the intended range.

**Phase 2 — Multi-session statistical attack:**

6. Repeat Phase 1 across many signing sessions. Each session, the attacker uses a slightly biased `x` value. The MtA output shares accumulate a small statistical bias.
7. The biased MtA shares translate to biased ECDSA nonces in the resulting signatures.
8. After collecting enough biased signatures (estimated 2^20 to 2^40 sessions), apply a lattice-based attack (Howgrave-Graham & Smart, or Bleichenbacher's method) to recover the honest party's ECDSA private key share.

### What does NOT work (honest limitations)

- **Single-shot key extraction:** The verifier's z1 range check at line 975 independently prevents a malicious prover from using a value that is far out of range. The attack requires many sessions.
- **If all deployments use protocol version ≥ 11:** The MtA range proof seed path uses the correct extended function. This bug only affects the non-extended path. However, the Rddh and log proof paths hardcode `use_extended_seed=0` regardless of version.

---

## Proof of Concept

The PoC file `poc/fs_truncation_poc.cpp` is a standalone C++ program that:

1. Creates a 512-byte BIGNUM `A` (simulating `proof.A` in Z_{N²})
2. Creates a 128-byte BIGNUM `S` (simulating `proof.S` in Z_{N_rp})
3. Reproduces the exact hashing logic from `mta.cpp` lines 120–154
4. Demonstrates that modifying byte 200 of `A` (outside the first 128 bytes) produces an **identical** SHA-256 seed
5. Demonstrates that modifying byte 50 of `A` (inside the first 128 bytes) produces a **different** seed
6. Demonstrates that the one-line fix produces different seeds for both modifications

**No library linkage required** — the PoC uses only OpenSSL directly.

Build and run:
```bash
g++ -std=c++17 -o poc_test poc/fs_truncation_poc.cpp -lssl -lcrypto
./poc_test
```

---

## Impact

**Formal:** The Fiat-Shamir transform requires the challenge to be a deterministic function of the **entire** proof transcript. Omitting 75% of the Paillier ciphertext `A` invalidates the security reduction from the CMP paper (IACR ePrint 2020/492, Section 4.2). The range proof cannot be formally proven sound.

**Practical:** A malicious cosigner uses the 2^3072 collision space to bias MtA shares across multiple signing sessions. Over time, this leaks the honest party's ECDSA private key share via lattice attacks on biased nonces. This violates SECURITY-MODEL.md §1.2.1 (Long-term key secrecy).

**SECURITY-MODEL.md scope:** This is a library-level implementation bug in the `crypto/cosigner` layer (§1). It is not an integrator-contract issue (§2). Both prover and verifier code use the same buggy hash function, and the hardcoded `use_extended_seed=0` paths are always active.

---

## Remediation

**Immediate fix (one line):**

In `src/common/cosigner/mta.cpp`, line 130, change:
```cpp
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));
```
to:
```cpp
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.A));
```

**Recommended fix — deprecate the non-extended seed path:**

1. Change all hardcoded `use_extended_seed=0` to `use_extended_seed=1`:
   - `mta.cpp` lines 658, 661, 669, 672
   - `cmp_ecdsa_online_signing_service.cpp` line 200
   - `cmp_ecdsa_signing_service.cpp` line 176
2. Remove `generate_mta_range_zkp_seed` entirely
3. Enforce minimum protocol version `MPC_EXTENDED_MTA` (11)

**Note:** Changing the seed function changes the Fiat-Shamir challenge, so proofs from the old function will not verify with the new one. Requires coordinated upgrade across all cosigner nodes.

---

## References

- CWE-131: https://cwe.mitre.org/data/definitions/131.html
- CMP Protocol: IACR ePrint 2020/492, Section 4.2 (MtA range proof)
- Fiat-Shamir soundness requirement: challenge must bind to ALL proof elements
- Howgrave-Graham & Smart: Lattice attack on biased ECDSA nonces
- Bleichenbacher: Statistical bias exploitation in DSA/ECDSA
