#ifndef OFB_H
#define OFB_H

#include <stddef.h>
#include <stdint.h>

void aes_ofb_encrypt(
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t length,
    const uint8_t iv[16],
    const void *ctx
);

void aes_ofb_decrypt(
    const uint8_t *ciphertext,
    uint8_t *plaintext,
    size_t length,
    const uint8_t iv[16],
    const void *ctx
);

#endif
