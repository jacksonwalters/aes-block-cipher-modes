#include <string.h>
#include "ecb.h"

void aes_ecb_encrypt(const uint8_t *plaintext, uint8_t *ciphertext,
                     size_t length, const void *ctx)
{
    size_t blocks = length / 16;
    for (size_t i = 0; i < blocks; ++i) {
        aes_block_wrapper(plaintext + i*16, ciphertext + i*16, ctx);
    }
}

void aes_ecb_decrypt(const uint8_t *ciphertext, uint8_t *plaintext,
                     size_t length, const void *ctx)
{
    size_t blocks = length / 16;
    for (size_t i = 0; i < blocks; ++i) {
        aes_block_wrapper_dec(ciphertext + i*16, plaintext + i*16, ctx);
    }
}
