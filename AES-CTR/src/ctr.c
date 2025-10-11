#include "ctr.h"
#include <string.h>
#include <stdint.h>

/* Increment counter block: treat last 4 bytes as big-endian 32-bit counter and add 1.
 * This is a common CTR layout: nonce || counter (32-bit). If you need a different
 * scheme (e.g., 64-bit counter), modify this function accordingly.
 */
void ctr_increment(uint8_t counter[CTR_BLOCK_SIZE]) {
    /* increment last 4 bytes as big-endian integer */
    for (int i = CTR_BLOCK_SIZE - 1; i >= CTR_BLOCK_SIZE - 4; --i) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

void aes_ctr_crypt(const uint8_t *in, uint8_t *out, size_t len,
                   const uint8_t counter[CTR_BLOCK_SIZE],
                   block_encrypt_fn encrypt, const void *rk)
{
    uint8_t ctr[CTR_BLOCK_SIZE];
    uint8_t keystream[CTR_BLOCK_SIZE];
    size_t processed = 0;

    /* copy initial counter so caller's buffer is not modified */
    memcpy(ctr, counter, CTR_BLOCK_SIZE);

    while (processed < len) {
        /* generate keystream block = AES_encrypt(counter) */
        encrypt(ctr, keystream, rk);

        size_t chunk = CTR_BLOCK_SIZE;
        if (len - processed < CTR_BLOCK_SIZE)
            chunk = len - processed;

        /* XOR chunk bytes */
        for (size_t i = 0; i < chunk; ++i) {
            out[processed + i] = in[processed + i] ^ keystream[i];
        }

        /* advance */
        processed += chunk;
        ctr_increment(ctr);
    }

    /* clear sensitive intermediate buffers */
    memset(keystream, 0, sizeof keystream);
    memset(ctr, 0, sizeof ctr);
}
