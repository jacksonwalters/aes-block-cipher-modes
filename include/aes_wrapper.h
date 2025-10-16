#ifndef AES_WRAPPER_H
#define AES_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

/* Context struct to pass round_keys, sbox, and key_len to aes_block_wrapper */
struct aes_ctx {
    const uint8_t *round_keys;
    const uint8_t *sbox;
    size_t key_len;  // 16, 24, or 32 bytes
};

/* Adapter to match encrypt_block_fn in cbc.h / ctr.h */
void aes_block_wrapper(const uint8_t in[16], uint8_t out[16], const void *ctx);

/* Adapter for decryption */
void aes_block_wrapper_dec(const uint8_t in[16], uint8_t out[16], const void *ctx);

#endif // AES_WRAPPER_H