# Bugcrowd Submission — Copy-Paste Ready

---

## Report Title

```
Fiat-Shamir Hash Truncation in MtA Range ZKP — 75% of proof.A Excluded from Challenge Derivation (mta.cpp:130)
```

---

## Bugcrowd VRT

```
Cryptographic Weakness > Broken Cryptography
```

If the program lists the VRT 1.15 blockchain/ZK additions, use:

```
Zero-Knowledge Proofs > Bit-Length Mismatches
```

---

## Severity

```
Medium (P3)
```

CVSS 3.1: `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` — **5.3**

Program tier match: **Medium — "Leaking bits of the private key"**

---

## Summary

In `src/common/cosigner/mta.cpp` line 130 of https://github.com/fireblocks/mpc-lib, the function `generate_mta_range_zkp_seed` hashes the Paillier ciphertext `proof.A` (~512 bytes) using `BN_num_bytes(proof.S)` (~128 bytes) as the length argument instead of `BN_num_bytes(proof.A)`. This causes 75% of the ciphertext to be excluded from the Fiat-Shamir challenge derivation, breaking the formal soundness of the MtA range zero-knowledge proof. A malicious cosigner can exploit the 2^3072 collision space to bias MtA shares across signing sessions, leaking bits of the honest party's ECDSA private key share.

---

## Description

The Multiplicative-to-Additive (MtA) protocol is the core building block of threshold ECDSA signing in the CMP protocol (IACR ePrint 2020/492). During MtA, each party proves in zero knowledge that their Paillier-encrypted value lies within a valid range. The proof's soundness depends on the Fiat-Shamir transform binding the challenge `e` to every element of the proof transcript.

The function `generate_mta_range_zkp_seed` (line 115) computes a SHA-256 seed for Fiat-Shamir challenge derivation. At line 130, it hashes `proof.A` — a Paillier ciphertext in Z_{N²} — but uses the wrong length:

```cpp
// mta.cpp lines 128-130 (BUGGY)
std::vector<uint8_t> n(BN_num_bytes(proof.A));       // allocates ~512 bytes
BN_bn2bin(proof.A, n.data());                         // writes all ~512 bytes of A
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // hashes only ~128 bytes (S's size!)
```

The correct version exists in the same file at line 104 (`generate_mta_range_zkp_extended_seed`):

```cpp
// mta.cpp line 104 (CORRECT)
hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A"); // hashes all 512 bytes
```

Key sizes from `cmp_setup_service.cpp` lines 24-25:
- **Paillier:** `sizeof(elliptic_curve256_scalar_t) * 8 * 8` = 2048 bits → N² ≈ 512 bytes → `proof.A` ≈ **512 bytes**
- **Ring-Pedersen:** `sizeof(elliptic_curve256_scalar_t) * 8 * 4` = 1024 bits → N_rp ≈ **128 bytes** → `proof.S` ≈ **128 bytes**

Serialization confirms: `proof.A` = `paillier_pub_n_size * 2` = 512 bytes (line 191), `proof.S` = `ring_pedersen_n_size` = 128 bytes (line 213).

**Result:** Only 128 of 512 bytes of `proof.A` enter the Fiat-Shamir hash. 384 bytes (3072 bits) are completely unbound by the challenge.

**Reachability:** The buggy path is always reachable — 4 call sites hardcode `use_extended_seed=0`:
- `mta.cpp` lines 658, 661, 669, 672 (Rddh and log proofs — active in ALL protocol versions)
- Additionally used when `version < MPC_EXTENDED_MTA (11)` — lines 552-558 (prover) and 988-994 (verifier)

---

## Steps to Reproduce

### Prerequisites

- Linux system with `g++` and `libssl-dev` (OpenSSL)
- No library build required — the PoC is standalone

### Step 1: Clone the target repository

```bash
git clone https://github.com/fireblocks/mpc-lib.git
cd mpc-lib
```

### Step 2: Verify the bug in source code

```bash
sed -n '128,130p' src/common/cosigner/mta.cpp
```

Output:
```cpp
    std::vector<uint8_t> n(BN_num_bytes(proof.A));
    BN_bn2bin(proof.A, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // right size of S is ensured during serialization
```

Line 130: the third argument to `SHA256_Update` should be `BN_num_bytes(proof.A)` but uses `BN_num_bytes(proof.S)`.

### Step 3: Compare with the correct version

```bash
sed -n '104p' src/common/cosigner/mta.cpp
```

Output:
```cpp
    hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A");
```

The extended seed function correctly hashes all 512 bytes of `proof.A`.

### Step 4: Confirm the sizes are different

```bash
grep -n 'PAILLIER_KEY_SIZE\|RING_PEDERSEN_KEY_SIZE' src/common/cosigner/cmp_setup_service.cpp | head -2
```

Output:
```
24:static const uint32_t PAILLIER_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 8; // 2048 bits
25:static const uint32_t RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4; // 1024 bits
```

- `sizeof(elliptic_curve256_scalar_t)` = 32 bytes
- Paillier: 32 × 8 × 8 = 2048 bits → N² ≈ 512 bytes (`proof.A`)
- Ring-Pedersen: 32 × 8 × 4 = 1024 bits → N_rp ≈ 128 bytes (`proof.S`)

So line 130 hashes only 128 of 512 bytes. **384 bytes (75%) of `proof.A` are excluded.**

### Step 5: Confirm buggy path is always reachable

```bash
grep -n 'use_extended_seed.*0' src/common/cosigner/mta.cpp | head -4
```

Output:
```
658:    ... /*use_extended_seed=*/0 ...
661:    ... /*use_extended_seed=*/0 ...
669:    ... /*use_extended_seed=*/0 ...
672:    ... /*use_extended_seed=*/0 ...
```

4 call sites hardcode `use_extended_seed=0`, forcing the buggy `generate_mta_range_zkp_seed` to be used in ALL protocol versions.

### Step 6: Save, compile and run the PoC

Save the file `fs_truncation_poc.cpp` (attached to this report) into the `mpc-lib` folder, then:

```bash
g++ -std=c++17 -w -o poc_test fs_truncation_poc.cpp -lssl -lcrypto
./poc_test
```

The PoC source is also available at: https://github.com/H1bbpskills/forp1vulns/blob/main/poc/fs_truncation_poc.cpp

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
1. Two different 512-byte Paillier ciphertexts (differing at byte 200) produce **identical** Fiat-Shamir seeds — the bug
2. A modification within the first 128 bytes **does** change the seed — confirming only bytes 0-127 are hashed
3. The one-line fix resolves it — all bytes of A are included

---

## Security Impact

### §1.2.1 property broken: Long-term key secrecy

The Fiat-Shamir transform requires the challenge `e` to be a deterministic function of the **entire** proof transcript. Omitting 75% of `proof.A` breaks the security reduction from CMP (IACR ePrint 2020/492, Section 4.2). The MtA range proof's soundness proof no longer holds.

### Adversary capability (§1.1 malicious cosigner)

A malicious cosigner — permitted under the threat model — can exploit this as follows:

**Per signing session:**
1. Participate in the MtA sub-protocol as a malicious cosigner
2. Choose a value `x` slightly outside the intended range
3. Compute `A = Enc(beta) * K^alpha mod N²` for many `(alpha, beta, r)` triples
4. All triples whose `A` values share the same first 128 bytes produce the **same** challenge `e` — giving 2^3072 collision classes
5. Search this space for a triple where `z1 = alpha + e*x` still passes the verifier's independent range check at line 975

**Multi-session accumulation:**
6. Repeat across many signing sessions, each with a slightly biased MtA share
7. Biased MtA shares translate to biased ECDSA nonces
8. Apply lattice-based key recovery (Howgrave-Graham & Smart, 1999) to extract the honest party's ECDSA private key share

### Independent defense (honest disclosure)

The `z1` range check at line 975 prevents single-shot forgery with a grossly out-of-range value. The attack requires many signing sessions to accumulate sufficient statistical bias. This is why we rate it Medium (leaking bits of the private key) rather than Critical.

### SECURITY-MODEL.md alignment

| Section | Status |
|---------|--------|
| §1.2.1 (Long-term key secrecy) | Broken — over multiple signing sessions |
| §4.2 (Incomplete ZKP generation) | Exact match — ZKP does not achieve claimed soundness |
| §4.7 (No practical attack path required) | Applies — theoretical soundness break is sufficient |
| §3 (Safe-by-design patterns) | None match — this is a real implementation bug |
| §6 (Frequent wrong claims) | None match — not drng, not RFC 6979, not key sizes |
| §2 (Integrator contract) | Not dependent on integrator — purely library-internal |

---

## Mitigation

### Immediate fix (one line)

In `src/common/cosigner/mta.cpp`, line 130, change:

```diff
- SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));
+ SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.A));
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

## Supporting Materials

- **PoC source code:** https://github.com/H1bbpskills/forp1vulns/blob/main/poc/fs_truncation_poc.cpp
- **Screen recording (.cast):** https://github.com/H1bbpskills/forp1vulns/blob/main/poc/exploit_recording.cast
- **Animated SVG:** https://github.com/H1bbpskills/forp1vulns/blob/main/poc/exploit_recording.svg
- **Screenshot of PoC output:** https://github.com/H1bbpskills/forp1vulns/blob/main/poc/exploit_result_screenshot.png

---

## References

- CWE-131: Incorrect Calculation of Buffer Size — https://cwe.mitre.org/data/definitions/131.html
- CMP Protocol: IACR ePrint 2020/492, Section 4.2 — https://eprint.iacr.org/2020/492
- Fiat-Shamir transform: challenge must bind to ALL proof elements (Fiat & Shamir, CRYPTO 1986)
- Howgrave-Graham & Smart (1999): Lattice attack on biased ECDSA nonces
- Bleichenbacher (2000): Statistical bias exploitation in DSA/ECDSA
- Fireblocks mpc-lib SECURITY-MODEL.md: §1.2.1, §4.2, §4.7
