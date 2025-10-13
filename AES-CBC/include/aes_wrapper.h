#ifndef AES_WRAPPER_H
#define AES_WRAPPER_H

#include <stdint.h>

#define AES_BLOCK_SIZE 16

/* Context struct for AES CTR/CBC wrappers */
struct aes_ctx {
    const uint8_t *round_keys;
    const uint8_t *sbox;
};

/* wrappers for encrypt/decrypt single AES blocks (adapter for our modes) */
void aes_block_wrapper(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const void *ctx);

void aes_block_wrapper_dec(const uint8_t in[AES_BLOCK_SIZE],
                           uint8_t out[AES_BLOCK_SIZE],
                           const void *ctx);

#endif /* AES_WRAPPER_H */
