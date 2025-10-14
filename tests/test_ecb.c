#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../include/ecb.h"
#include "../include/aes_wrapper.h"
#include "../include/aes_128.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

int main(void) {
    // NIST SP 800-38A AES-128 ECB test vector
    const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    const uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };

    const uint8_t expected_ciphertext[16] = {
        0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
    };

    uint8_t round_keys[176];
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion(key, round_keys, sbox);

    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox };

    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};

    // Encrypt
    aes_ecb_encrypt(plaintext, ciphertext, 16, &ctx);

    // Decrypt
    aes_ecb_decrypt(ciphertext, decrypted, 16, &ctx);

    // Verify encryption matches NIST vector
    if (memcmp(ciphertext, expected_ciphertext, 16) != 0) {
        fprintf(stderr, "ECB encryption FAILED\n");
        return 1;
    }

    // Verify decryption matches plaintext
    if (memcmp(decrypted, plaintext, 16) != 0) {
        fprintf(stderr, "ECB decryption FAILED\n");
        return 2;
    }

    printf("ECB round-trip OK — plaintext recovered correctly.\n");
    printf("Plaintext: ");
    for (size_t i = 0; i < 16; ++i) printf("%02x", plaintext[i]);
    printf("\n");

    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < 16; ++i) printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}
