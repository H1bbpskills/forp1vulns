// Standalone PoC: Fiat-Shamir Hash Truncation in MtA Range ZKP
// Demonstrates that 75% of proof.A is excluded from the FS challenge hash
//
// Build:
//   cd mpc-lib && mkdir -p build && cd build
//   cmake .. && make -j$(nproc)
//   cd ../..
//   g++ -std=c++17 -I mpc-lib/include -I mpc-lib/src/common \
//       poc/fs_truncation_poc.cpp -o poc_test \
//       -L mpc-lib/build/src/common -lcosigner -lcrypto_utils \
//       -lssl -lcrypto -lpthread
//   ./poc_test

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

// Reproduces the EXACT logic from mta.cpp lines 115-155
// (generate_mta_range_zkp_seed) in isolation, so no library linkage needed.
static void hash_A_buggy(const BIGNUM *A, const BIGNUM *S,
                         const uint8_t *prefix, size_t prefix_len,
                         uint8_t *digest) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    // Hash some prefix bytes (stands in for salt+aad+message+commitment)
    SHA256_Update(&ctx, prefix, prefix_len);

    // --- THE BUG: line 130 of mta.cpp ---
    std::vector<uint8_t> buf(BN_num_bytes(A));
    BN_bn2bin(A, buf.data());
    SHA256_Update(&ctx, buf.data(), BN_num_bytes(S));  // WRONG: uses S's size

    SHA256_Final(digest, &ctx);
}

static void hash_A_fixed(const BIGNUM *A, const BIGNUM *S,
                         const uint8_t *prefix, size_t prefix_len,
                         uint8_t *digest) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, prefix, prefix_len);

    std::vector<uint8_t> buf(BN_num_bytes(A));
    BN_bn2bin(A, buf.data());
    SHA256_Update(&ctx, buf.data(), BN_num_bytes(A));  // CORRECT: uses A's size

    SHA256_Final(digest, &ctx);
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main() {
    printf("=== Fiat-Shamir Hash Truncation PoC ===\n\n");

    // Simulate the key sizes from cmp_setup_service.cpp:
    //   PAILLIER_KEY_SIZE  = 2048 bits -> N = 256 bytes -> N^2 = 512 bytes
    //   RING_PEDERSEN_KEY_SIZE = 1024 bits -> N_rp = 128 bytes
    const int A_BYTES = 512;   // proof.A lives in Z_{N^2}, ~512 bytes
    const int S_BYTES = 128;   // proof.S lives in Z_{N_rp}, ~128 bytes

    // Generate a random 512-byte A (simulating a Paillier ciphertext)
    BIGNUM *A1 = BN_new();
    BN_rand(A1, A_BYTES * 8, BN_RAND_TOP_ONE, 0);

    // Generate a random 128-byte S (simulating a Ring-Pedersen commitment)
    BIGNUM *S = BN_new();
    BN_rand(S, S_BYTES * 8, BN_RAND_TOP_ONE, 0);

    printf("Step 1: Verify sizes match the library's defaults\n");
    printf("  BN_num_bytes(A) = %d  (expected ~%d)\n", BN_num_bytes(A1), A_BYTES);
    printf("  BN_num_bytes(S) = %d  (expected ~%d)\n", BN_num_bytes(S), S_BYTES);
    printf("  Bytes of A actually hashed (buggy) = %d\n", BN_num_bytes(S));
    printf("  Bytes of A SKIPPED          = %d (%.0f%%)\n\n",
           BN_num_bytes(A1) - BN_num_bytes(S),
           100.0 * (BN_num_bytes(A1) - BN_num_bytes(S)) / BN_num_bytes(A1));

    // Create A2 = A1 but with different bytes AFTER position 128
    // BN_bn2bin writes big-endian: byte 0 = MSB, byte 511 = LSB
    // The buggy code hashes bytes [0..127] only.
    // So we flip a byte at position 0 (MSB, within the hashed range)
    // and separately at position 200 (outside the hashed range).

    // --- Test 1: Modify byte OUTSIDE the hashed range (byte 200) ---
    BIGNUM *A2 = BN_dup(A1);
    std::vector<uint8_t> a2_buf(BN_num_bytes(A2));
    BN_bn2bin(A2, a2_buf.data());
    a2_buf[200] ^= 0xFF;  // flip byte 200 (outside first 128 bytes)
    BN_bin2bn(a2_buf.data(), a2_buf.size(), A2);

    uint8_t prefix[] = "test_salt_aad_data";
    uint8_t digest1[32], digest2[32];

    hash_A_buggy(A1, S, prefix, sizeof(prefix), digest1);
    hash_A_buggy(A2, S, prefix, sizeof(prefix), digest2);

    printf("Step 2: Modify byte 200 of A (OUTSIDE hashed range)\n");
    print_hex("  Seed with original A", digest1, 32);
    print_hex("  Seed with modified A", digest2, 32);
    if (memcmp(digest1, digest2, 32) == 0) {
        printf("  RESULT: IDENTICAL — byte 200 of A is NOT in the hash!\n");
        printf("  >>> BUG CONFIRMED: modifying A does not change the FS challenge <<<\n\n");
    } else {
        printf("  RESULT: Different (unexpected)\n\n");
    }

    // --- Test 2: Modify byte INSIDE the hashed range (byte 50) ---
    BIGNUM *A3 = BN_dup(A1);
    std::vector<uint8_t> a3_buf(BN_num_bytes(A3));
    BN_bn2bin(A3, a3_buf.data());
    a3_buf[50] ^= 0xFF;  // flip byte 50 (inside first 128 bytes)
    BN_bin2bn(a3_buf.data(), a3_buf.size(), A3);

    uint8_t digest3[32];
    hash_A_buggy(A3, S, prefix, sizeof(prefix), digest3);

    printf("Step 3: Modify byte 50 of A (INSIDE hashed range)\n");
    print_hex("  Seed with original A", digest1, 32);
    print_hex("  Seed with byte-50  A", digest3, 32);
    if (memcmp(digest1, digest3, 32) == 0) {
        printf("  RESULT: IDENTICAL (unexpected)\n\n");
    } else {
        printf("  RESULT: Different — byte 50 IS in the hash (as expected)\n\n");
    }

    // --- Test 3: Show the FIXED version catches both modifications ---
    uint8_t fixed1[32], fixed2[32];
    hash_A_fixed(A1, S, prefix, sizeof(prefix), fixed1);
    hash_A_fixed(A2, S, prefix, sizeof(prefix), fixed2);

    printf("Step 4: Fixed version (using BN_num_bytes(A) as length)\n");
    print_hex("  Fixed seed original A", fixed1, 32);
    print_hex("  Fixed seed modified A", fixed2, 32);
    if (memcmp(fixed1, fixed2, 32) == 0) {
        printf("  RESULT: IDENTICAL (would mean fix failed)\n\n");
    } else {
        printf("  RESULT: Different — fix correctly includes all bytes of A\n\n");
    }

    // --- Summary ---
    int buggy_collision = (memcmp(digest1, digest2, 32) == 0);
    int fixed_different = (memcmp(fixed1, fixed2, 32) != 0);
    int inside_different = (memcmp(digest1, digest3, 32) != 0);

    printf("=== SUMMARY ===\n");
    printf("Buggy hash: modifying byte 200 of A produces same seed?  %s\n",
           buggy_collision ? "YES (BUG)" : "NO");
    printf("Buggy hash: modifying byte 50 of A produces diff seed?   %s\n",
           inside_different ? "YES (only first 128 bytes matter)" : "NO");
    printf("Fixed hash: modifying byte 200 of A produces diff seed?  %s\n",
           fixed_different ? "YES (fix works)" : "NO");

    if (buggy_collision && fixed_different && inside_different) {
        printf("\n>>> ALL CHECKS PASSED: Vulnerability confirmed <<<\n");
        printf("  - %d of %d bytes of A are excluded from the FS challenge\n",
               A_BYTES - S_BYTES, A_BYTES);
        printf("  - A malicious prover has 2^%d collision classes for A\n",
               (A_BYTES - S_BYTES) * 8);
        printf("  - The one-line fix (use BN_num_bytes(proof.A)) resolves it\n");
    }

    BN_free(A1);
    BN_free(A2);
    BN_free(A3);
    BN_free(S);
    return 0;
}
