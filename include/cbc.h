#ifndef CBC_H
#define CBC_H

#include <stddef.h>
#include <stdint.h>
#include "aes_wrapper.h"  // provides encrypt_block_fn and decrypt_block_fn

#define AES_BLOCK 16

/* ===============================
 *  Block function typedefs
 * =============================== */
typedef void (*encrypt_block_fn)(const uint8_t in[AES_BLOCK],
                                 uint8_t out[AES_BLOCK],
                                 const void *ctx);

typedef void (*decrypt_block_fn)(const uint8_t in[AES_BLOCK],
                                 uint8_t out[AES_BLOCK],
                                 const void *ctx);

/* ===============================
 *  Unpadded CBC (raw block-wise)
 * =============================== */
int aes_cbc_encrypt_unpadded(const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len,
                             const uint8_t iv[AES_BLOCK],
                             encrypt_block_fn encrypt,
                             const void *ctx);

int aes_cbc_decrypt_unpadded(const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len,
                             const uint8_t iv[AES_BLOCK],
                             decrypt_block_fn decrypt,
                             const void *ctx);

/* ===============================
 *  Padded CBC (PKCS#7)
 * =============================== */
int aes_cbc_encrypt_padded(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len,
                           const uint8_t iv[AES_BLOCK],
                           encrypt_block_fn encrypt,
                           const void *ctx);

int aes_cbc_decrypt_padded(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len,
                           const uint8_t iv[AES_BLOCK],
                           decrypt_block_fn decrypt,
                           const void *ctx);

#endif /* CBC_H */
