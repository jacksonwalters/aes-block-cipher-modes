#ifndef CFB_H
#define CFB_H

#include <stddef.h>
#include <stdint.h>

void aes_cfb_encrypt(
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t length,
    const uint8_t *iv,
    const void *ctx
);

void aes_cfb_decrypt(
    const uint8_t *ciphertext,
    uint8_t *plaintext,
    size_t length,
    const uint8_t *iv,
    const void *ctx
);

#endif
