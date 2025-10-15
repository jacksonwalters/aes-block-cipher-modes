#ifndef GCM_H
#define GCM_H

#include <stdint.h>
#include <stddef.h>
#include "aes_wrapper.h"

#define GCM_BLOCK_SIZE 16

/* GCM context */
struct gcm_ctx {
    struct aes_ctx aes;       /* AES context for block operations */
    uint8_t H[GCM_BLOCK_SIZE]; /* GHASH subkey */
    uint8_t J0[GCM_BLOCK_SIZE]; /* Initial counter block */

    uint8_t round_keys[240];  /* Max round keys for AES-256 */
    uint8_t sbox[256];        /* AES S-box */
};

/* Initialize GCM context with key and IV */
void gcm_init(struct gcm_ctx *ctx,
              const uint8_t *key, size_t key_len,
              const uint8_t *iv, size_t iv_len);

/* Encrypt plaintext and compute tag */
void gcm_encrypt(struct gcm_ctx *ctx,
                 const uint8_t *plaintext, size_t len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *ciphertext,
                 uint8_t *tag, size_t tag_len);

/* Decrypt ciphertext and verify tag. Returns 0 if tag matches, -1 otherwise */
int gcm_decrypt(struct gcm_ctx *ctx,
                const uint8_t *ciphertext, size_t len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *tag, size_t tag_len,
                uint8_t *plaintext);

#endif /* GCM_H */