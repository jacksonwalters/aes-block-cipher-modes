#ifndef ECB_H
#define ECB_H

#include <stddef.h>
#include <stdint.h>

#include "aes_wrapper.h"  // for ctx struct

void aes_ecb_encrypt(const uint8_t *plaintext, uint8_t *ciphertext,
                     size_t length, const void *ctx);

void aes_ecb_decrypt(const uint8_t *ciphertext, uint8_t *plaintext,
                     size_t length, const void *ctx);

int aes_ecb_encrypt_padded(const uint8_t *in, size_t in_len,
                           const void *ctx,
                           uint8_t **out, size_t *out_len);

int aes_ecb_decrypt_padded(const uint8_t *in, size_t in_len,
                           const void *ctx,
                           uint8_t **out, size_t *out_len);

#endif
