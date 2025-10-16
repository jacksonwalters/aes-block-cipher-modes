#include <stdint.h>
#include <stddef.h>

#include "../include/aes_128.h"
#include "../include/aes_192.h"
#include "../include/aes_256.h"
#include "../include/sbox.h"

/* Context struct to pass round_keys, sbox, and key_len to aes_block_wrapper */
struct aes_ctx {
    const uint8_t *round_keys;
    const uint8_t *sbox;
    size_t key_len;  // 16, 24, or 32 bytes
};

/* Adapter to match encrypt_block_fn in cbc.h / ctr.h */
void aes_block_wrapper(const uint8_t in[16], uint8_t out[16], const void *ctx) {
    const struct aes_ctx *aes = (const struct aes_ctx *)ctx;
    
    if (aes->key_len == 16) {
        aes128_encrypt_block(in, out, aes->round_keys, aes->sbox);
    } else if (aes->key_len == 24) {
        aes192_encrypt_block(in, out, aes->round_keys, aes->sbox);
    } else if (aes->key_len == 32) {
        aes256_encrypt_block(in, out, aes->round_keys, aes->sbox);
    }
}

/* Adapter for decryption */
void aes_block_wrapper_dec(const uint8_t in[16], uint8_t out[16], const void *ctx) {
    const struct aes_ctx *aes = (const struct aes_ctx *)ctx;
    
    if (aes->key_len == 16) {
        aes128_decrypt_block(in, out, aes->round_keys, aes->sbox);
    } else if (aes->key_len == 24) {
        aes192_decrypt_block(in, out, aes->round_keys, aes->sbox);
    } else if (aes->key_len == 32) {
        aes256_decrypt_block(in, out, aes->round_keys, aes->sbox);
    }
}