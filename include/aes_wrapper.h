#ifndef AES_WRAPPER_H
#define AES_WRAPPER_H

#include <stdint.h>

#define AES_BLOCK_SIZE 16

/* Context struct for AES block operations */
struct aes_ctx {
    const uint8_t *round_keys;
    const uint8_t *sbox;
};

/* Wrappers for single AES block encrypt/decrypt */
void aes_block_wrapper(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const void *ctx);

void aes_block_wrapper_dec(const uint8_t in[AES_BLOCK_SIZE],
                           uint8_t out[AES_BLOCK_SIZE],
                           const void *ctx);

#endif /* AES_WRAPPER_H */
