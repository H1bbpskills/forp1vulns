# Triager Reproduction Guide

## Fiat-Shamir Hash Truncation in MtA Range ZKP

**Severity:** Medium — Leaking bits of the private key
**Target:** `src/common/cosigner/mta.cpp`, line 130
**Time to reproduce:** ~2 minutes
**Requirements:** Linux, `g++`, `libssl-dev` (OpenSSL)

---

## Quick Summary (30 seconds)

Open `mta.cpp` line 130 in https://github.com/fireblocks/mpc-lib:

```cpp
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));  // BUG: uses S's size (128 bytes)
```

Should be:

```cpp
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.A));  // FIX: uses A's size (512 bytes)
```

`proof.A` is ~512 bytes (Paillier ciphertext in Z_{N²}). `proof.S` is ~128 bytes (Ring-Pedersen commitment). Only 128 of 512 bytes enter the Fiat-Shamir challenge hash. 75% of `proof.A` is unbound.

---

## Full Reproduction (copy-paste)

Run these 6 commands in order. Each one is independent and verifiable.

### Step 1: Clone the target repository

```bash
git clone https://github.com/fireblocks/mpc-lib.git
cd mpc-lib
```

### Step 2: See the bug

```bash
sed -n '128,130p' src/common/cosigner/mta.cpp
```

**Expected output:**
```
    std::vector<uint8_t> n(BN_num_bytes(proof.A));
    BN_bn2bin(proof.A, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // right size of S is ensured during serialization
```

**What to look for:** Line 128 allocates a buffer using `proof.A`'s size (~512 bytes). Line 129 writes all of `proof.A` into it. But line 130 hashes only `BN_num_bytes(proof.S)` bytes (~128 bytes) instead of `BN_num_bytes(proof.A)` (~512 bytes).

### Step 3: See the correct version (same file, different function)

```bash
sed -n '104p' src/common/cosigner/mta.cpp
```

**Expected output:**
```
    hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A");
```

**What to look for:** The extended seed function at line 104 correctly hashes `proof.A` using `verifier_paillier_pub_n_size * 2` = 512 bytes. The buggy function at line 130 uses the wrong size.

### Step 4: Confirm the sizes are different

```bash
grep -n 'PAILLIER_KEY_SIZE\|RING_PEDERSEN_KEY_SIZE' src/common/cosigner/cmp_setup_service.cpp | head -2
```

**Expected output:**
```
24:static const uint32_t PAILLIER_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 8;
25:static const uint32_t RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4;
```

**What to look for:** `sizeof(elliptic_curve256_scalar_t)` = 32 bytes.
- Paillier: 32 * 8 * 8 = 2048 bits → N² ≈ **512 bytes** (this is `proof.A`)
- Ring-Pedersen: 32 * 8 * 4 = 1024 bits → N_rp ≈ **128 bytes** (this is `proof.S`)

So line 130 hashes only 128 of 512 bytes. **384 bytes (75%) of `proof.A` are excluded from the Fiat-Shamir challenge.**

### Step 5: Confirm the buggy path is always reachable

```bash
grep -n 'use_extended_seed.*0' src/common/cosigner/mta.cpp | head -4
```

**Expected output:**
```
658:    ... /*use_extended_seed=*/0 ...
661:    ... /*use_extended_seed=*/0 ...
669:    ... /*use_extended_seed=*/0 ...
672:    ... /*use_extended_seed=*/0 ...
```

**What to look for:** 4 call sites hardcode `use_extended_seed=0`, which forces the buggy `generate_mta_range_zkp_seed` function (line 115) to be used instead of the correct `generate_mta_range_zkp_extended_seed` (line 83). These call sites are in the Rddh and log proofs — **active in ALL protocol versions**, not just old ones.

### Step 6: Compile and run the PoC

```bash
git clone https://github.com/H1bbpskills/forp1vulns.git
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
  Seed with modified A: <hex>
  RESULT: IDENTICAL — byte 200 of A is NOT in the hash!
  >>> BUG CONFIRMED: modifying A does not change the FS challenge <<<

Step 3: Modify byte 50 of A (INSIDE hashed range)
  Seed with original A: <hex>
  Seed with byte-50  A: <hex>
  RESULT: Different — byte 50 IS in the hash (as expected)

Step 4: Fixed version (using BN_num_bytes(A) as length)
  Fixed seed original A: <hex>
  Fixed seed modified A: <hex>
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
1. Two different 512-byte Paillier ciphertexts that differ only at byte 200 produce **identical** Fiat-Shamir seeds (BUG)
2. Two ciphertexts that differ at byte 50 (within the first 128 bytes) produce **different** seeds — confirming only bytes 0-127 are hashed
3. The one-line fix (using `BN_num_bytes(A)` instead of `BN_num_bytes(S)`) makes all bytes count

---

## Why This Matters (Security Impact)

### Formal impact
The Fiat-Shamir transform requires the challenge `e` to be a deterministic function of the **entire** proof transcript. Omitting 75% of `proof.A` breaks the security reduction from CMP (IACR ePrint 2020/492, Section 4.2). The MtA range ZKP's soundness proof no longer holds.

### Practical attack path
A malicious cosigner (permitted under SECURITY-MODEL.md §1.1) can:
1. Search 2^3072 collision classes for `proof.A` values that share the same first 128 bytes
2. Find favorable `(alpha, beta, r)` triples that produce a slightly biased MtA share while still passing the independent `z1` range check at line 975
3. Repeat across many signing sessions to accumulate statistical bias in ECDSA nonces
4. Apply lattice-based key recovery (Howgrave-Graham & Smart) to extract the honest party's key share

### Independent defense (honest disclosure)
The `z1` range check at line 975 prevents single-shot forgery with a grossly out-of-range value. The attack requires many sessions to accumulate bias. This is why we rate it Medium (leaking bits of the private key) rather than Critical.

### SECURITY-MODEL.md alignment
- **§1.2.1 broken:** Long-term key secrecy, over multiple protocol executions
- **§4.2 match:** Incomplete ZKP generation — does not achieve claimed soundness
- **§4.7:** Practical attack path not required for a valid finding
- **Not §3/§6:** Not a safe-by-design pattern or frequent wrong claim
- **Not §2:** Not an integrator-contract issue — purely library-internal

---

## One-Line Fix

`src/common/cosigner/mta.cpp`, line 130:

```diff
- SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));
+ SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.A));
```
