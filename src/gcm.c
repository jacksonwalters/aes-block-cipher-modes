#include "gcm.h"
#include "sbox.h"
#include "key_expansion_128.h"
#include "key_expansion_256.h"
#include "aes_wrapper.h"
#include <string.h>
#include <stdio.h>

/* XOR two blocks (16 bytes) */
static void xor_block(uint8_t out[GCM_BLOCK_SIZE],
                      const uint8_t a[GCM_BLOCK_SIZE],
                      const uint8_t b[GCM_BLOCK_SIZE]) {
    for (int i = 0; i < GCM_BLOCK_SIZE; i++)
        out[i] = a[i] ^ b[i];
}

/* GHASH multiplication in GF(2^128) */
static void ghash_mult(uint8_t out[GCM_BLOCK_SIZE],
                       const uint8_t X[GCM_BLOCK_SIZE],
                       const uint8_t H[GCM_BLOCK_SIZE]) {
    uint8_t Z[GCM_BLOCK_SIZE] = {0};
    uint8_t V[GCM_BLOCK_SIZE];
    memcpy(V, H, GCM_BLOCK_SIZE);

    for (int i = 0; i < GCM_BLOCK_SIZE; i++) {
        for (int j = 7; j >= 0; j--) {
            if ((X[i] >> j) & 1)
                for (int k = 0; k < GCM_BLOCK_SIZE; k++)
                    Z[k] ^= V[k];
            /* Shift V right by 1 in GF(2^128) with reduction */
            int carry = 0;
            for (int k = 0; k < GCM_BLOCK_SIZE; k++) {
                int tmp = V[k];
                V[k] = (tmp >> 1) | carry;
                carry = (tmp & 1) ? 0x80 : 0x00;
            }
            if (carry)
                V[0] ^= 0xe1; /* Reduction polynomial */
        }
    }
    memcpy(out, Z, GCM_BLOCK_SIZE);
}

/* GHASH over arbitrary length input */
static void ghash(uint8_t out[GCM_BLOCK_SIZE],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *c, size_t c_len,
                  const uint8_t H[GCM_BLOCK_SIZE]) {
    uint8_t Y[GCM_BLOCK_SIZE] = {0};
    size_t i;

    /* Process AAD blocks */
    for (i = 0; i + GCM_BLOCK_SIZE <= aad_len; i += GCM_BLOCK_SIZE) {
        xor_block(Y, Y, aad + i);
        ghash_mult(Y, Y, H);
    }
    if (i < aad_len) {
        uint8_t tmp[GCM_BLOCK_SIZE] = {0};
        memcpy(tmp, aad + i, aad_len - i);
        xor_block(Y, Y, tmp);
        ghash_mult(Y, Y, H);
    }

    /* Process ciphertext blocks */
    for (i = 0; i + GCM_BLOCK_SIZE <= c_len; i += GCM_BLOCK_SIZE) {
        xor_block(Y, Y, c + i);
        ghash_mult(Y, Y, H);
    }
    if (i < c_len) {
        uint8_t tmp[GCM_BLOCK_SIZE] = {0};
        memcpy(tmp, c + i, c_len - i);
        xor_block(Y, Y, tmp);
        ghash_mult(Y, Y, H);
    }

    /* Length block */
    uint8_t len_block[GCM_BLOCK_SIZE] = {0};
    uint64_t aad_bits = aad_len * 8;
    uint64_t c_bits = c_len * 8;
    for (int j = 0; j < 8; j++) {
        len_block[7 - j] = (aad_bits >> (8*j)) & 0xFF;
        len_block[15 - j] = (c_bits >> (8*j)) & 0xFF;
    }
    xor_block(Y, Y, len_block);
    ghash_mult(Y, Y, H);

    memcpy(out, Y, GCM_BLOCK_SIZE);
}

/* Initialize GCM context */
void gcm_init(struct gcm_ctx *ctx, const uint8_t *key, size_t key_len,
              const uint8_t *iv, size_t iv_len) {

    // iniitialize AES S-box
    initialize_aes_sbox(ctx->sbox);

    if (key_len == 16) {
        aes_key_expansion(key, ctx->round_keys, ctx->sbox);
    } else if (key_len == 32) {
        aes_key_expansion_256(key, ctx->round_keys, ctx->sbox);
    } else {
        fprintf(stderr, "Unsupported AES key length\n");
        return;
    }

    ctx->aes.round_keys = ctx->round_keys;
    ctx->aes.sbox = ctx->sbox;

    /* Compute H = AES(K, 0^128) */
    uint8_t zero[16] = {0};
    aes_block_wrapper(zero, ctx->H, &ctx->aes);

    /* IV handling */
    memset(ctx->J0, 0, 16);
    if (iv_len == 12) {
        memcpy(ctx->J0, iv, 12);
        ctx->J0[15] = 0x01;
    }
    else {
        /* GHASH the IV */
    }
}


/* Encrypt with AES-GCM */
void gcm_encrypt(struct gcm_ctx *ctx,
                 const uint8_t *plaintext, size_t len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *ciphertext,
                 uint8_t *tag, size_t tag_len) {

    if (tag_len > 16) tag_len = 16;

    uint8_t ctr[GCM_BLOCK_SIZE];
    memcpy(ctr, ctx->J0, GCM_BLOCK_SIZE);

    /* CTR-mode encryption */
    for (size_t i = 0; i < len; i += GCM_BLOCK_SIZE) {
        uint8_t block[GCM_BLOCK_SIZE];
        aes_block_wrapper(ctr, block, &ctx->aes);
        size_t n = (len - i < GCM_BLOCK_SIZE) ? (len - i) : GCM_BLOCK_SIZE;
        for (size_t j = 0; j < n; j++)
            ciphertext[i + j] = plaintext[i + j] ^ block[j];

        /* Increment counter (32-bit) */
        for (int k = 15; k >= 12; k--) {
            if (++ctr[k] != 0) break;
        }
    }

    /* Compute GHASH */
    uint8_t ghash_out[GCM_BLOCK_SIZE];
    ghash(ghash_out, aad, aad_len, ciphertext, len, ctx->H);

    /* Compute tag: T = GHASH ⊕ AES(K, J0) */
    uint8_t S[GCM_BLOCK_SIZE];
    aes_block_wrapper(ctx->J0, S, &ctx->aes);
    for (size_t i = 0; i < tag_len; i++)
        tag[i] = ghash_out[i] ^ S[i];
}

/* Decrypt with AES-GCM, verify tag */
int gcm_decrypt(struct gcm_ctx *ctx,
                const uint8_t *ciphertext, size_t len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *tag, size_t tag_len,
                uint8_t *plaintext) {

    if (tag_len > 16) tag_len = 16;

    /* Decrypt CTR */
    uint8_t ctr[GCM_BLOCK_SIZE];
    memcpy(ctr, ctx->J0, GCM_BLOCK_SIZE);
    for (size_t i = 0; i < len; i += GCM_BLOCK_SIZE) {
        uint8_t block[GCM_BLOCK_SIZE];
        aes_block_wrapper(ctr, block, &ctx->aes);
        size_t n = (len - i < GCM_BLOCK_SIZE) ? (len - i) : GCM_BLOCK_SIZE;
        for (size_t j = 0; j < n; j++)
            plaintext[i + j] = ciphertext[i + j] ^ block[j];

        for (int k = 15; k >= 12; k--) {
            if (++ctr[k] != 0) break;
        }
    }

    /* Recompute tag */
    uint8_t ghash_out[GCM_BLOCK_SIZE];
    ghash(ghash_out, aad, aad_len, ciphertext, len, ctx->H);

    uint8_t S[GCM_BLOCK_SIZE];
    aes_block_wrapper(ctx->J0, S, &ctx->aes);

    for (size_t i = 0; i < tag_len; i++)
        if (tag[i] != (ghash_out[i] ^ S[i]))
            return -1; /* Tag mismatch */

    return 0;
}
