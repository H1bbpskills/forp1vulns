# Fiat-Shamir Hash Truncation in MtA Range ZKP Weakens Proof Soundness

## Summary

In `src/common/cosigner/mta.cpp` line 130, the non-extended Fiat-Shamir seed generation function `generate_mta_range_zkp_seed` hashes the Paillier ciphertext `proof.A` using the byte-length of `proof.S` (a Ring-Pedersen commitment) instead of `proof.A`'s own byte-length. With the library's default key sizes (2048-bit Paillier, 1024-bit Ring-Pedersen), this causes only 128 out of ~512 bytes of the ciphertext to be included in the challenge derivation, leaving 75% of the ciphertext value unbound by the Fiat-Shamir transform and breaking the soundness of the MtA range proof.

## Description

The Multiplicative-to-Additive (MtA) protocol is the core building block of threshold ECDSA signing in the CMP protocol. During MtA, each party proves in zero knowledge that their Paillier-encrypted value lies within a valid range. The proof's soundness relies on the Fiat-Shamir transform binding the challenge `e` to every element of the proof transcript.

The function `generate_mta_range_zkp_seed` (line 115) computes the SHA-256 seed for challenge derivation. At line 130, it hashes `proof.A` — a Paillier ciphertext living in Z_{N^2} — but passes `BN_num_bytes(proof.S)` as the length argument to `SHA256_Update` instead of `BN_num_bytes(proof.A)`:

```cpp
// mta.cpp lines 128-130
std::vector<uint8_t> n(BN_num_bytes(proof.A));   // allocates ~512 bytes for A
BN_bn2bin(proof.A, n.data());                     // writes all ~512 bytes of A
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // hashes only ~128 bytes (S's size)
```

The key sizes configured in `cmp_setup_service.cpp` are:
- Paillier: 2048-bit key → N is 256 bytes → N^2 is 512 bytes → `proof.A` is ~512 bytes
- Ring-Pedersen: 1024-bit key → N_rp is 128 bytes → `proof.S` is ~128 bytes

The serialization functions in the same file confirm these sizes: `proof.A` is serialized with `paillier_pub_n_size * 2` (512 bytes) at line 191, while `proof.S` is serialized with `ring_pedersen_n_size` (128 bytes) at line 213.

The corrected version of this function exists in the same file as `generate_mta_range_zkp_extended_seed` (line 86), which properly hashes A with its full size:
```cpp
// mta.cpp line 104 (correct extended version)
hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A");
```

The non-extended path is active when the protocol version is below `MPC_EXTENDED_MTA` (version 11). The MtA response code at lines 552-558 selects between the two paths based on version. Additionally, the Rddh and log proof generation at lines 658-672 hardcode `use_extended_seed=0`, always using the buggy path for those specific proofs regardless of version.

## Severity

Medium-High

CVSS 3.1 Vector: AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N
CVSS 3.1 Score: 6.8

The attack complexity is High because exploiting the truncated hash to forge a range proof requires cryptographic effort beyond simply modifying the unbound bytes — the attacker must also satisfy the algebraic verification equations with the modified ciphertext. However, the confidentiality and integrity impacts are both High because a successful exploit breaks the MtA range proof soundness, which is the primary defense against key share extraction in threshold ECDSA.

## Steps to Reproduce

1. Clone the repository:
   ```
   git clone https://github.com/fireblocks/mpc-lib
   cd mpc-lib
   ```

2. Confirm the key sizes. Open `src/common/cosigner/cmp_setup_service.cpp`:
   ```
   Line 24: static const uint32_t PAILLIER_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 8;
   // = 32 * 8 * 8 = 2048 bits → N = 256 bytes → N^2 = 512 bytes
   
   Line 25: static const uint32_t RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4;
   // = 32 * 8 * 4 = 1024 bits → N_rp = 128 bytes
   ```

3. Open `src/common/cosigner/mta.cpp` and locate the two seed functions:
   - **Buggy (non-extended):** `generate_mta_range_zkp_seed` at line 115
   - **Correct (extended):** `generate_mta_range_zkp_extended_seed` at line 83

4. At line 130 in the buggy version, observe:
   ```cpp
   std::vector<uint8_t> n(BN_num_bytes(proof.A));     // ~512 bytes allocated
   BN_bn2bin(proof.A, n.data());                       // ~512 bytes written
   SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // only ~128 bytes hashed
   ```
   The third argument should be `BN_num_bytes(proof.A)` but instead uses `BN_num_bytes(proof.S)`.

5. At line 104 in the correct version, observe:
   ```cpp
   hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A"); // full 512 bytes hashed
   ```

6. Confirm the serialization sizes match (different sizes for A and S):
   - Line 191: `BN_bn2binpad(proof.A, ptr, paillier_pub_n_size * 2)` → 512 bytes
   - Line 213: `BN_bn2binpad(proof.S, ptr, ring_pedersen_n_size)` → 128 bytes

7. Confirm the buggy path is reachable in production:
   - Lines 552-558: non-extended seed used when `version < MPC_EXTENDED_MTA (11)`
   - Lines 658, 661: `use_extended_seed=0` hardcoded for Rddh proof generation
   - Lines 669, 672: `use_extended_seed=0` hardcoded for log proof generation
   - `cmp_ecdsa_online_signing_service.cpp` line 200: `use_extended_seed=0` hardcoded for Rddh verification
   - `cmp_ecdsa_signing_service.cpp` line 176: `use_extended_seed=0` hardcoded for log proof verification

## Security Impact

The Fiat-Shamir transform's soundness depends on the challenge `e` being a deterministic function of the entire proof transcript. By hashing only 128 of ~512 bytes of the Paillier ciphertext `proof.A`, the challenge is not fully bound to A's value. A malicious prover can modify the upper 384 bytes of A (which represent the high-order portion of the ciphertext value in Z_{N^2}) without altering the derived challenge `e`.

This breaks the range proof's soundness guarantee: the MtA range proof is supposed to ensure that the encrypted value lies within a specific range (preventing a malicious party from injecting arbitrary values into the MtA protocol). With a partially-unbound ciphertext, a malicious cosigner can craft proofs for ciphertexts encoding out-of-range values that still pass verification.

The concrete security consequence is a violation of SECURITY-MODEL.md §1.2.1 (Long-term key secrecy): over multiple signing sessions, a malicious cosigner exploiting biased MtA shares could gradually extract information about the honest party's ECDSA private key share, eventually recovering the full key share.

This is a library-level implementation bug — not an integrator-contract issue — because the Fiat-Shamir hash computation is entirely within the library's responsibility. Both the prover and verifier code paths are affected (the same buggy seed function is called on both sides), so the bug is consistent but unsound.

## Mitigation

**Immediate fix — correct the hash length (one-line change):**

In `src/common/cosigner/mta.cpp`, line 130, change:
```cpp
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));
```
to:
```cpp
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.A));
```

**Recommended longer-term fix — deprecate the non-extended seed path:**

1. Change all hardcoded `use_extended_seed=0` call sites to `use_extended_seed=1`:
   - `mta.cpp` lines 658, 661, 669, 672
   - `cmp_ecdsa_online_signing_service.cpp` line 200
   - `cmp_ecdsa_signing_service.cpp` line 176
2. Remove the `generate_mta_range_zkp_seed` function entirely
3. Enforce a minimum protocol version of `MPC_EXTENDED_MTA` (11) to prevent fallback to the legacy path

**Note:** Changing the seed function changes the Fiat-Shamir challenge, so proofs generated with the old function will not verify with the new one. This requires a coordinated upgrade across all cosigner nodes.
