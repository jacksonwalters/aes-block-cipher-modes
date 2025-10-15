#include "gcm.h"
#include "ctr.h"
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

static void print_block(const char *label, const uint8_t *b) {
    printf("%s: ", label);
    for (int i = 0; i < GCM_BLOCK_SIZE; i++) printf("%02x", b[i]);
    printf("\n");
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

    printf("[GHASH] Start\n");

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

    print_block("[GHASH] Final Y", Y);

    memcpy(out, Y, GCM_BLOCK_SIZE);
}

/* Initialize GCM context */
void gcm_init(struct gcm_ctx *ctx, const uint8_t *key, size_t key_len,
              const uint8_t *iv, size_t iv_len) {

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
    print_block("[GCM init] H", ctx->H);

    /* IV handling */
    memset(ctx->J0, 0, 16);
    if (iv_len == 12) {
        memcpy(ctx->J0, iv, 12);
        ctx->J0[15] = 0x01;
    } else {
        /* TODO: GHASH IV for non-96-bit IVs */
    }

    print_block("[GCM init] J0", ctx->J0);
}

/* Encrypt with AES-GCM */
void gcm_encrypt(struct gcm_ctx *ctx,
                 const uint8_t *plaintext, size_t len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *ciphertext,
                 uint8_t *tag, size_t tag_len) {

    if (tag_len > 16) tag_len = 16;

    /* Start CTR at inc32(J0) */
    uint8_t counter[GCM_BLOCK_SIZE];
    memcpy(counter, ctx->J0, GCM_BLOCK_SIZE);
    ctr_increment(counter);
    print_block("[Encrypt] Counter start", counter);

    /* CTR encryption */
    aes_ctr_crypt(plaintext, ciphertext, len, counter,
                  aes_block_wrapper, &ctx->aes);

    printf("[Encrypt] Ciphertext: ");
    for (size_t i = 0; i < len; i++) printf("%02x", ciphertext[i]);
    printf("\n");

    /* GHASH over AAD and ciphertext */
    uint8_t ghash_out[GCM_BLOCK_SIZE];
    ghash(ghash_out, aad, aad_len, ciphertext, len, ctx->H);

    /* Compute tag: T = GHASH ⊕ AES(K, J0) */
    uint8_t S[GCM_BLOCK_SIZE];
    aes_block_wrapper(ctx->J0, S, &ctx->aes);
    print_block("[Encrypt] AES(K,J0)", S);

    for (size_t i = 0; i < tag_len; i++)
        tag[i] = ghash_out[i] ^ S[i];

    printf("[Encrypt] Tag: ");
    for (size_t i = 0; i < tag_len; i++) printf("%02x", tag[i]);
    printf("\n");
}

/* Decrypt with AES-GCM, verify tag */
int gcm_decrypt(struct gcm_ctx *ctx,
                const uint8_t *ciphertext, size_t len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *tag, size_t tag_len,
                uint8_t *plaintext) {

    if (tag_len > 16) tag_len = 16;

    /* Recompute tag */
    uint8_t ghash_out[GCM_BLOCK_SIZE];
    ghash(ghash_out, aad, aad_len, ciphertext, len, ctx->H);

    uint8_t S[GCM_BLOCK_SIZE];
    aes_block_wrapper(ctx->J0, S, &ctx->aes);

    uint8_t computed_tag[16];
    for (size_t i = 0; i < tag_len; i++)
        computed_tag[i] = ghash_out[i] ^ S[i];

    printf("[Decrypt] Tag expected: ");
    for (size_t i = 0; i < tag_len; i++) printf("%02x", tag[i]);
    printf("\n");
    printf("[Decrypt] Tag computed: ");
    for (size_t i = 0; i < tag_len; i++) printf("%02x", computed_tag[i]);
    printf("\n");

    if (memcmp(tag, computed_tag, tag_len) != 0) {
        fprintf(stderr, "[Decrypt] Tag mismatch!\n");
        return -1;
    }

    /* Start CTR at inc32(J0) */
    uint8_t counter[GCM_BLOCK_SIZE];
    memcpy(counter, ctx->J0, GCM_BLOCK_SIZE);
    ctr_increment(counter);
    print_block("[Decrypt] Counter start", counter);

    /* Decrypt ciphertext */
    aes_ctr_crypt(ciphertext, plaintext, len, counter,
                  aes_block_wrapper, &ctx->aes);

    return 0;
}
