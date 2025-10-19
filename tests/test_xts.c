/*
 * Basic unit test for XTS module.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/xts.h"
#include "../include/aes_wrapper.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

static const uint8_t key1[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};
static const uint8_t key2[16] = {
    0x0F,0x0E,0x0D,0x0C,0x0B,0x0A,0x09,0x08,
    0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00
};

static int test_roundtrip(const uint8_t *pt, size_t len, uint64_t data_unit) {
    uint8_t ct[1024], out[1024];
    memset(ct, 0, sizeof(ct));
    memset(out, 0, sizeof(out));

    uint8_t sbox[256];
    initialize_aes_sbox(sbox);

    uint8_t round_keys1[176], round_keys2[176];
    aes_key_expansion_128(key1, round_keys1, sbox);
    aes_key_expansion_128(key2, round_keys2, sbox);

    struct aes_ctx ctx_k1 = { round_keys1, sbox, 16 };
    struct aes_ctx ctx_k2 = { round_keys2, sbox, 16 };

    int r = xts_encrypt((aes_block_fn)aes_block_wrapper, &ctx_k1,
                        (aes_block_fn)aes_block_wrapper, &ctx_k2,
                        data_unit, pt, len, ct);
    if (r != XTS_OK) return r;

    r = xts_decrypt((aes_block_fn)aes_block_wrapper_dec, &ctx_k1,
                    (aes_block_fn)aes_block_wrapper, &ctx_k2,
                    data_unit, ct, len, out);
    if (r != XTS_OK) return r;

    if (memcmp(pt, out, len) != 0) return -1;
    return 1;
}

int main(void) {
    uint8_t buf[256];
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = (uint8_t)i;

    size_t lengths[] = {1, 7, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 128};
    int all_ok = 1;

    for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i) {
        size_t len = lengths[i];
        uint64_t du = 42 + i;
        printf("Test length=%zu, data_unit=%llu... ", len, (unsigned long long)du);

        if (len < 16) {
            printf("SKIPPED (<16 bytes)\n");
            continue;
        }

        int r = test_roundtrip(buf, len, du);
        if (r == 1) {
            printf("OK\n");
        } else if (r == XTS_ERR_INVALID) {
            printf("INVALID LENGTH\n");
            all_ok = 0;
        } else if (r == -1) {
            printf("ROUNDTRIP MISMATCH\n");
            all_ok = 0;
        } else {
            printf("FAILED (code=%d)\n", r);
            all_ok = 0;
        }
    }

    if (all_ok) {
        printf("All XTS roundtrip tests passed.\n");
        return 0;
    } else {
        printf("Some XTS roundtrip tests failed.\n");
        return 2;
    }
}
