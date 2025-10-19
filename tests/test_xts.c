/*
 * Basic unit test for XTS module.
 *
 * This test uses a trivial "mock AES" so it runs without your AES key schedule.
 * The mock AES is its own inverse (XOR with 0xAA) to permit round-trip testing.
 *
 * When you run this test in your repo you can replace the mock functions with
 * the real `aes_block_wrapper` + `aes_ctx` as appropriate.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/xts.h"
#include "../include/aes_wrapper.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

/* mock AES: simple byte-wise XOR with 0xAA -- invertible and deterministic */
static void mock_aes_enc(const uint8_t in[16], uint8_t out[16], const void *ctx) {
    (void)ctx;
    for (int i = 0; i < 16; ++i) out[i] = in[i] ^ 0xAA;
}
static void mock_aes_dec(const uint8_t in[16], uint8_t out[16], const void *ctx) {
    /* same as encrypt because XOR with 0xAA is its own inverse */
    mock_aes_enc(in, out, ctx);
}

/* mock tweak AES (same behavior) */
static void mock_tweak_enc(const uint8_t in[16], uint8_t out[16], const void *ctx) {
    (void)ctx;
    for (int i = 0; i < 16; ++i) out[i] = in[i] ^ 0x55; /* different constant to vary tweak */
}

static const uint8_t key1[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t key2[16] = {
    0x0F, 0x0E, 0x0D, 0x0C,
    0x0B, 0x0A, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04,
    0x03, 0x02, 0x01, 0x00
};

static int test_roundtrip(const uint8_t *pt, size_t len, uint64_t data_unit) {
    uint8_t ct[1024];
    uint8_t out[1024];
    memset(ct, 0, sizeof(ct));
    memset(out, 0, sizeof(out));

    // initialize AES sbox
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);

    // lengths to test
    uint8_t round_keys1[176];
    uint8_t round_keys2[176];

    aes_key_expansion_128(key1, round_keys1, sbox);
    aes_key_expansion_128(key2, round_keys2, sbox);

    struct aes_ctx ctx_k1;
    struct aes_ctx ctx_k2;

    ctx_k1.round_keys = round_keys1;
    ctx_k1.sbox = sbox;
    ctx_k1.key_len = 16;

    ctx_k2.round_keys = round_keys2;
    ctx_k2.sbox = sbox;
    ctx_k2.key_len = 16;

    int r = xts_encrypt((aes_block_fn)aes_block_wrapper, &ctx_k1,
                        (aes_block_fn)aes_block_wrapper, &ctx_k2,
                        data_unit, pt, len, ct);
    if (r != XTS_OK) {
        printf("encrypt failed: %d\n", r);
        return 0;
    }
    r = xts_decrypt((aes_block_fn)aes_block_wrapper_dec, &ctx_k1,
                    (aes_block_fn)aes_block_wrapper, &ctx_k2,
                    data_unit, ct, len, out);
    if (r != XTS_OK) {
        printf("decrypt failed: %d\n", r);
        return 0;
    }
    if (memcmp(pt, out, len) != 0) {
        printf("roundtrip mismatch (len=%zu)\n", len);
        return 0;
    }
    return 1;
}

int main(void) {
    /* test vectors (varying lengths including partial block cases) */
    uint8_t buf[256];
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = (uint8_t)i;

    size_t lengths[] = {1, 7, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 128};
    int all_ok = 1;
    for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i) {
        size_t len = lengths[i];
        uint64_t du = 42 + i; /* some data unit numbers */
        printf("Test length=%zu, data_unit=%llu... ", len, (unsigned long long)du);
        if (!test_roundtrip(buf, len, du)) {
            printf("FAILED\n");
            all_ok = 0;
        } else {
            printf("OK\n");
        }
    }

    if (all_ok) {
        printf("All XTS roundtrip tests passed (mock AES).\n");
        return 0;
    } else {
        printf("Some XTS roundtrip tests failed.\n");
        return 2;
    }
}
