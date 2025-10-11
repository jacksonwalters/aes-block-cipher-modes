#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../include/ctr.h"
#include "../include/aes_wrapper.h"
#include "aes.h"
#include "key_expansion.h"
#include "sbox.h"

int main(void) {
    /* AES key & round keys */
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t round_keys[176];
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);

    aes_key_expansion(key, round_keys, sbox);

    /* AES context for CTR */
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox };

    /* sample plaintext */
    const uint8_t pt[] = "The quick brown fox jumps over 13 lazy dogs!";
    size_t len = strlen((const char*)pt);

    uint8_t ciphertext[256] = {0};
    uint8_t recovered[256] = {0};

    /* 16-byte initial counter block (12-byte nonce | 4-byte counter) */
    uint8_t iv[16] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x00,0x00,0x00,0x01
    };

    /* Encrypt */
    aes_ctr_crypt(pt, ciphertext, len, iv, aes_block_wrapper, &ctx);

    /* Decrypt */
    aes_ctr_crypt(ciphertext, recovered, len, iv, aes_block_wrapper, &ctx);

    /* verify */
    if (memcmp(pt, recovered, len) != 0) {
        fprintf(stderr, "CTR round-trip FAILED\n");
        return 2;
    }

    printf("CTR round-trip OK — plaintext recovered correctly.\n");
    printf("Plaintext:  '%s'\n", (const char*)pt);
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < len; ++i) printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}