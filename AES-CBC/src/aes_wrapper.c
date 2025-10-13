#include <stdint.h>

#include "../../AES/aes128_c/aes.h"
#include "../../AES/aes128_c/key_expansion.h"
#include "../../AES/aes128_c/sbox.h"


/* Context struct to pass round_keys and sbox to aes_block_wrapper */
struct aes_ctx {
    const uint8_t *round_keys;
    const uint8_t *sbox;
};

/* Adapter to match encrypt_block_fn in cbc.h / ctr.h */
void aes_block_wrapper(const uint8_t in[16], uint8_t out[16], const void *ctx) {
    const struct aes_ctx *aes = (const struct aes_ctx *)ctx;
    aes_encrypt_block(in, out, aes->round_keys, aes->sbox);
}

/* Adapter for decryption */
void aes_block_wrapper_dec(const uint8_t in[16], uint8_t out[16], const void *ctx) {
    const struct aes_ctx *aes = (const struct aes_ctx *)ctx;
    aes_decrypt_block(in, out, aes->round_keys, aes->sbox);
}
