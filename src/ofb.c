#include "ofb.h"
#include <string.h>
#include "aes_wrapper.h"  // for aes_block_wrapper

void aes_ofb_encrypt(
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t length,
    const uint8_t iv[16],
    const void *ctx
) {
    uint8_t feedback[16];
    uint8_t keystream[16];
    size_t processed = 0;

    memcpy(feedback, iv, 16);

    while (processed < length) {
        aes_block_wrapper(feedback, keystream, ctx);

        size_t chunk = 16;
        if (length - processed < 16) chunk = length - processed;

        for (size_t i = 0; i < chunk; ++i)
            ciphertext[processed + i] = plaintext[processed + i] ^ keystream[i];

        memcpy(feedback, keystream, 16);
        processed += chunk;
    }

    memset(feedback, 0, 16);
    memset(keystream, 0, 16);
}

void aes_ofb_decrypt(
    const uint8_t *ciphertext,
    uint8_t *plaintext,
    size_t length,
    const uint8_t iv[16],
    const void *ctx
) {
    // OFB decryption is identical to encryption
    aes_ofb_encrypt(ciphertext, plaintext, length, iv, ctx);
}
