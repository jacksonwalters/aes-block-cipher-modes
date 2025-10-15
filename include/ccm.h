#ifndef CCM_H
#define CCM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE 16

// Unified AES block encryption function type
typedef void (*block_encrypt_fn)(const uint8_t in[AES_BLOCK_SIZE],
                                 uint8_t out[AES_BLOCK_SIZE],
                                 const void *key_ctx);

// AES-CCM encryption
int ccm_encrypt(
    const void *key_ctx,
    block_encrypt_fn encrypt,
    const uint8_t *nonce, size_t n,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t payload_len,
    uint8_t *ciphertext, size_t *ciphertext_len,
    size_t t
);

// AES-CCM decryption
int ccm_decrypt(
    const void *key_ctx,
    block_encrypt_fn encrypt,
    const uint8_t *nonce, size_t n,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len,
    size_t t
);

#ifdef CCM_DEBUG
#include <stdio.h>
#define CCM_LOG(fmt, ...) \
    do { fprintf(stderr, "[CCM] " fmt "\n", ##__VA_ARGS__); } while(0)
#else
#define CCM_LOG(fmt, ...) do {} while(0)
#endif

#ifdef __cplusplus
}
#endif

#endif // CCM_H
