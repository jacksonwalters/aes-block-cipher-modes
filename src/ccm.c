#include "ccm.h"
#include "ctr.h"
#include "cbc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define AES_BLK AES_BLOCK_SIZE

/* XOR helper */
static inline void xor_block(uint8_t out[AES_BLK],
                             const uint8_t a[AES_BLK],
                             const uint8_t b[AES_BLK]) {
    for (int i = 0; i < AES_BLK; i++) out[i] = a[i] ^ b[i];
}

/* Build B0 block (CCM §6.1) */
static void build_b0(uint8_t b0[AES_BLK], size_t t, size_t n, size_t payload_len, const uint8_t *nonce, int has_aad) {
    size_t q = 15 - n;
    uint8_t flags = 0;
    if (has_aad) flags |= 0x40;
    flags |= (uint8_t)(((t - 2) / 2) << 3);
    flags |= (uint8_t)((q - 1) & 0x07);
    b0[0] = flags;

    memcpy(b0 + 1, nonce, n);

    /* write payload length in q-byte big-endian */
    for (size_t i = 0; i < q; i++) {
        b0[15 - i] = (uint8_t)(payload_len >> (8 * i));
    }
}

/* Build initial counter block for CTR */
static void build_ctr0(uint8_t ctr[AES_BLK], size_t n, const uint8_t *nonce) {
    size_t q = 15 - n;
    ctr[0] = (uint8_t)(q - 1);
    memcpy(ctr + 1, nonce, n);
    memset(ctr + 1 + n, 0, q);
}

/* Format AAD */
static size_t format_aad(uint8_t **out, size_t aad_len, const uint8_t *aad) {
    if (aad_len == 0) return 0;
    size_t total = 2 + aad_len;
    size_t padded = ((total + AES_BLK - 1) / AES_BLK) * AES_BLK;
    uint8_t *buf = (uint8_t*)calloc(padded, 1);
    if (!buf) return 0;
    buf[0] = (uint8_t)(aad_len >> 8);
    buf[1] = (uint8_t)(aad_len & 0xff);
    memcpy(buf + 2, aad, aad_len);
    *out = buf;
    return padded;
}

int ccm_encrypt(const void *key_ctx,
                block_encrypt_fn encrypt,
                const uint8_t *nonce, size_t n,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *plaintext, size_t payload_len,
                uint8_t *ciphertext, size_t *ciphertext_len,
                size_t t)
{
    if (!encrypt || !nonce || !ciphertext || !ciphertext_len) return -1;
    if (n < 7 || n > 13) return -2;
    if (!(t == 4 || t == 6 || t == 8 || t == 10 || t == 12 || t == 14 || t == 16)) return -3;

#ifdef CCM_DEBUG
    CCM_LOG("Encrypting payload_len=%zu, aad_len=%zu, t=%zu", payload_len, aad_len, t);
#endif

    /* Step 1: Build B0 */
    uint8_t b0[AES_BLK];
    build_b0(b0, t, n, payload_len, nonce, aad_len > 0);

    /* Step 2: Format AAD */
    uint8_t *aad_formatted = NULL;
    size_t aad_formatted_len = format_aad(&aad_formatted, aad_len, aad);

    /* Step 3: Build CBC-MAC input */
    size_t mac_len = AES_BLK + aad_formatted_len;
    if (payload_len > 0) {
        size_t padded_payload_len = ((payload_len + AES_BLK - 1) / AES_BLK) * AES_BLK;
        mac_len += padded_payload_len;
    }
    uint8_t *mac_input = (uint8_t*)calloc(mac_len, 1);
    size_t offset = 0;
    memcpy(mac_input + offset, b0, AES_BLK);
    offset += AES_BLK;
    if (aad_formatted_len > 0) {
        memcpy(mac_input + offset, aad_formatted, aad_formatted_len);
        offset += aad_formatted_len;
    }
    if (payload_len > 0) {
        memcpy(mac_input + offset, plaintext, payload_len);
    }

    /* Step 4: CBC-MAC */
    uint8_t X[AES_BLK] = {0};
    for (size_t i = 0; i < mac_len; i += AES_BLK) {
        uint8_t blk[AES_BLK];
        xor_block(blk, X, mac_input + i);
        encrypt(blk, X, key_ctx);
    }

    /* Step 5: CTR encrypt */
    uint8_t ctr[AES_BLK];
    build_ctr0(ctr, n, nonce);
    uint8_t s0[AES_BLK];
    encrypt(ctr, s0, key_ctx);

    /* Encrypt plaintext */
    ctr_increment(ctr);
    aes_ctr_crypt(plaintext, ciphertext, payload_len, ctr, encrypt, key_ctx);

    /* Compute tag */
    uint8_t tag_buf[AES_BLK];
    xor_block(tag_buf, X, s0);
    memcpy(ciphertext + payload_len, tag_buf, t);
    *ciphertext_len = payload_len + t;

    free(aad_formatted);
    free(mac_input);

#ifdef CCM_DEBUG
    CCM_LOG("Encryption complete, tag_len=%zu", t);
#endif
    return 0;
}

int ccm_decrypt(const void *key_ctx,
                block_encrypt_fn encrypt,
                const uint8_t *nonce, size_t n,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext, size_t *plaintext_len,
                size_t t)
{
    if (ciphertext_len < t) return -1;
    size_t payload_len = ciphertext_len - t;

#ifdef CCM_DEBUG
    CCM_LOG("Decrypting payload_len=%zu, aad_len=%zu, t=%zu", payload_len, aad_len, t);
#endif

    /* Step 1: Decrypt payload */
    uint8_t ctr[AES_BLK];
    build_ctr0(ctr, n, nonce);
    ctr_increment(ctr);
    aes_ctr_crypt(ciphertext, plaintext, payload_len, ctr, encrypt, key_ctx);

    /* Step 2: Recompute CBC-MAC */
    uint8_t b0[AES_BLK];
    build_b0(b0, t, n, payload_len, nonce, aad_len > 0);
    uint8_t *aad_formatted = NULL;
    size_t aad_formatted_len = format_aad(&aad_formatted, aad_len, aad);

    size_t mac_len = AES_BLK + aad_formatted_len;
    if (payload_len > 0) {
        size_t padded_payload_len = ((payload_len + AES_BLK - 1) / AES_BLK) * AES_BLK;
        mac_len += padded_payload_len;
    }
    uint8_t *mac_input = (uint8_t*)calloc(mac_len, 1);
    size_t offset = 0;
    memcpy(mac_input + offset, b0, AES_BLK);
    offset += AES_BLK;
    if (aad_formatted_len > 0) {
        memcpy(mac_input + offset, aad_formatted, aad_formatted_len);
        offset += aad_formatted_len;
    }
    if (payload_len > 0) {
        memcpy(mac_input + offset, plaintext, payload_len);
    }

    uint8_t X[AES_BLK] = {0};
    for (size_t i = 0; i < mac_len; i += AES_BLK) {
        uint8_t blk[AES_BLK];
        xor_block(blk, X, mac_input + i);
        encrypt(blk, X, key_ctx);
    }

    /* Step 3: Verify tag */
    uint8_t s0[AES_BLK];
    build_ctr0(ctr, n, nonce);
    encrypt(ctr, s0, key_ctx);

    uint8_t expected_tag[AES_BLK];
    xor_block(expected_tag, X, s0);

    const uint8_t *received_tag = ciphertext + payload_len;
    int diff = 0;
    for (size_t i = 0; i < t; i++) diff |= (expected_tag[i] ^ received_tag[i]);

    free(aad_formatted);
    free(mac_input);

    if (diff != 0) {
        memset(plaintext, 0, payload_len);
        return -2;
    }

    *plaintext_len = payload_len;
    return 0;
}
