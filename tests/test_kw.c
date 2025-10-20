#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../include/kw.h"
#include "../include/aes_wrapper.h"
#include "../include/key_expansion_128.h"
#include "../include/key_expansion_192.h"
#include "../include/key_expansion_256.h"
#include "../include/sbox.h"

/* small helper to print hex for debugging */
static void hexprint(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02X", buf[i]);
}

/* prepare aes_ctx from KEK: generate sbox and round_keys appropriate for kek_len */
static int make_aes_ctx(const uint8_t *kek, size_t kek_len, struct aes_ctx *ctx,
                        uint8_t **round_keys_storage)
{
    if (!kek || !ctx || !round_keys_storage) return -1;

    uint8_t *sbox = (uint8_t*)malloc(256);
    if (!sbox) return -1;
    initialize_aes_sbox(sbox);

    /* Round-key sizes in your implementation:
       - AES-128 -> 176 bytes
       - AES-192 -> 208 bytes
       - AES-256 -> 240 bytes
     */
    uint8_t *rk = NULL;
    if (kek_len == 16) {
        rk = (uint8_t*)malloc(176);
        if (!rk) { free(sbox); return -1; }
        aes_key_expansion_128(kek, rk, sbox);
    } else if (kek_len == 24) {
        rk = (uint8_t*)malloc(208);
        if (!rk) { free(sbox); return -1; }
        aes_key_expansion_192(kek, rk, sbox);
    } else if (kek_len == 32) {
        rk = (uint8_t*)malloc(240);
        if (!rk) { free(sbox); return -1; }
        aes_key_expansion_256(kek, rk, sbox);
    } else {
        free(sbox);
        return -1;
    }

    ctx->round_keys = rk;
    ctx->sbox = sbox;
    ctx->key_len = kek_len;
    *round_keys_storage = rk;
    return 0;
}

static void free_aes_ctx(struct aes_ctx *ctx)
{
    if (!ctx) return;
    if (ctx->round_keys) free((void*)ctx->round_keys);
    if (ctx->sbox) free((void*)ctx->sbox);
    ctx->round_keys = NULL;
    ctx->sbox = NULL;
}

/* A test vector driver that does wrap -> unwrap and checks round-trip.
   If expected_wrapped != NULL, it will also compare the produced wrapped
   bytes against that expected value (byte-for-byte). */
static int run_kw_vector(const uint8_t *kek, size_t kek_len,
                         const uint8_t *plaintext, size_t plen,
                         const uint8_t *expected_wrapped, size_t expected_wrapped_len)
{
    struct aes_ctx ctx;
    uint8_t *rk_storage = NULL;
    if (make_aes_ctx(kek, kek_len, &ctx, &rk_storage) != 0) {
        fprintf(stderr, "Failed to init AES ctx for kek_len=%zu\n", kek_len);
        return 1;
    }

    size_t clen = plen + 8;
    uint8_t *wrapped = (uint8_t*)malloc(clen);
    uint8_t *unwrapped = (uint8_t*)malloc(plen);
    if (!wrapped || !unwrapped) {
        fprintf(stderr, "Out of memory\n");
        free(wrapped); free(unwrapped);
        free_aes_ctx(&ctx);
        return 1;
    }
    memset(wrapped, 0, clen);
    memset(unwrapped, 0, plen);

    int rc = kw_wrap(plaintext, plen, wrapped, &ctx);
    if (rc != 0) {
        fprintf(stderr, "kw_wrap failed (kek_len=%zu plen=%zu)\n", kek_len, plen);
        free(wrapped); free(unwrapped); free_aes_ctx(&ctx);
        return 1;
    }

    if (expected_wrapped != NULL) {
        if (expected_wrapped_len != clen || memcmp(wrapped, expected_wrapped, clen) != 0) {
            fprintf(stderr, "KW wrap mismatch (kek_len=%zu plen=%zu)\nExpected: ", kek_len, plen);
            hexprint(expected_wrapped, expected_wrapped_len);
            fprintf(stderr, "\nGot:      ");
            hexprint(wrapped, clen);
            fprintf(stderr, "\n");
            free(wrapped); free(unwrapped); free_aes_ctx(&ctx);
            return 1;
        }
    }

    rc = kw_unwrap(wrapped, clen, unwrapped, &ctx);
    if (rc != 0) {
        fprintf(stderr, "kw_unwrap failed (kek_len=%zu plen=%zu)\n", kek_len, plen);
        free(wrapped); free(unwrapped); free_aes_ctx(&ctx);
        return 1;
    }

    if (memcmp(unwrapped, plaintext, plen) != 0) {
        fprintf(stderr, "KW round-trip mismatch (kek_len=%zu plen=%zu)\n", kek_len, plen);
        fprintf(stderr, "Recovered: ");
        hexprint(unwrapped, plen);
        fprintf(stderr, "\nExpected : ");
        hexprint(plaintext, plen);
        fprintf(stderr, "\n");
        free(wrapped); free(unwrapped); free_aes_ctx(&ctx);
        return 1;
    }

    free(wrapped);
    free(unwrapped);
    free_aes_ctx(&ctx);
    return 0;
}

int main(void)
{
    int fail = 0;

    /* --- RFC 3394 examples (sections 4.1 - 4.6) --- */

    /* 4.1: 128-bit KEK wrapping 128 bits of Key Data
       We also validate the wrapped output equals the RFC canonical bytes. */
    {
        const uint8_t kek128[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
        };
        const uint8_t keydata128[16] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
        };
        const uint8_t expected_wrapped_4_1[24] = {
            0x1F,0xA6,0x8B,0x0A,0x81,0x12,0xB4,0x47,
            0xAE,0xF3,0x4B,0xD8,0xFB,0x5A,0x7B,0x82,
            0x9D,0x3E,0x86,0x23,0x71,0xD2,0xCF,0xE5
        };

        if (run_kw_vector(kek128, sizeof(kek128), keydata128, sizeof(keydata128),
                          expected_wrapped_4_1, sizeof(expected_wrapped_4_1)) != 0) {
            fprintf(stderr, "RFC 3394 section 4.1 FAILED\n");
            fail = 1;
        } else {
            printf("RFC 4.1 (128-bit KEK, 128-bit keydata): passed\n");
        }
    }

    /* 4.2: 192-bit KEK wrapping 128 bits of Key Data (round-trip check) */
    {
        const uint8_t kek192[24] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
        };
        const uint8_t keydata128[16] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
        };

        if (run_kw_vector(kek192, sizeof(kek192), keydata128, sizeof(keydata128),
                          NULL, 0) != 0) {
            fprintf(stderr, "RFC 3394 section 4.2 FAILED\n");
            fail = 1;
        } else {
            printf("RFC 4.2 (192-bit KEK, 128-bit keydata): passed (round-trip)\n");
        }
    }

    /* 4.3: 256-bit KEK wrapping 128 bits of Key Data (round-trip check) */
    {
        const uint8_t kek256[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
        };
        const uint8_t keydata128[16] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
        };

        if (run_kw_vector(kek256, sizeof(kek256), keydata128, sizeof(keydata128),
                          NULL, 0) != 0) {
            fprintf(stderr, "RFC 3394 section 4.3 FAILED\n");
            fail = 1;
        } else {
            printf("RFC 4.3 (256-bit KEK, 128-bit keydata): passed (round-trip)\n");
        }
    }

    /* 4.4: 192-bit KEK wrapping 192 bits (24 bytes) of Key Data */
    {
        const uint8_t kek192[24] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
        };
        const uint8_t keydata192[24] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
        };

        if (run_kw_vector(kek192, sizeof(kek192), keydata192, sizeof(keydata192),
                          NULL, 0) != 0) {
            fprintf(stderr, "RFC 3394 section 4.4 FAILED\n");
            fail = 1;
        } else {
            printf("RFC 4.4 (192-bit KEK, 192-bit keydata): passed (round-trip)\n");
        }
    }

    /* 4.5: 256-bit KEK wrapping 192 bits (24 bytes) of Key Data */
    {
        const uint8_t kek256[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
        };
        const uint8_t keydata192[24] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
        };

        if (run_kw_vector(kek256, sizeof(kek256), keydata192, sizeof(keydata192),
                          NULL, 0) != 0) {
            fprintf(stderr, "RFC 3394 section 4.5 FAILED\n");
            fail = 1;
        } else {
            printf("RFC 4.5 (256-bit KEK, 192-bit keydata): passed (round-trip)\n");
        }
    }

    /* 4.6: 256-bit KEK wrapping 256 bits (32 bytes) of Key Data */
    {
        const uint8_t kek256[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
        };
        const uint8_t keydata256[32] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
        };

        if (run_kw_vector(kek256, sizeof(kek256), keydata256, sizeof(keydata256),
                          NULL, 0) != 0) {
            fprintf(stderr, "RFC 3394 section 4.6 FAILED\n");
            fail = 1;
        } else {
            printf("RFC 4.6 (256-bit KEK, 256-bit keydata): passed (round-trip)\n");
        }
    }

    if (fail) {
        fprintf(stderr, "\nOne or more RFC 3394 vectors FAILED.\n");
        return 1;
    }

    printf("\nAll RFC 3394 test vectors passed (round-trip). ✅\n");
    return 0;
}
