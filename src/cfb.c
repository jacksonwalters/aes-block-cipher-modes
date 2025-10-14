#include <stdint.h>
#include <string.h>
#include "../include/cfb.h"
#include "../include/aes_wrapper.h"   // for aes_block_wrapper
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

void aes_cfb_encrypt(
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t length,
    const uint8_t *iv,
    const void *ctx
) {
    uint8_t buffer[16];
    uint8_t feedback[16];

    memcpy(feedback, iv, 16);
    aes_block_wrapper(feedback, buffer, &ctx); // encrypt IV

    for (size_t i = 0; i < length; i++) {
        ciphertext[i] = plaintext[i] ^ buffer[i % 16];
        feedback[i % 16] = ciphertext[i];

        if ((i % 16) == 15 && i + 1 < length) {
            aes_block_wrapper(feedback, buffer, &ctx);
        }
    }
}

void aes_cfb_decrypt(
    const uint8_t *ciphertext,
    uint8_t *plaintext,
    size_t length,
    const uint8_t *iv,
    const void *ctx
) {
    uint8_t buffer[16];
    uint8_t feedback[16];

    memcpy(feedback, iv, 16);
    aes_block_wrapper(feedback, buffer, &ctx); // encrypt IV

    for (size_t i = 0; i < length; i++) {
        plaintext[i] = ciphertext[i] ^ buffer[i % 16];
        feedback[i % 16] = ciphertext[i];

        if ((i % 16) == 15 && i + 1 < length) {
            aes_block_wrapper(feedback, buffer, &ctx);
        }
    }
}
