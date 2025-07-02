#include <stdio.h>
#include <stdint.h>
#include "sbox.h"
#include "key_expansion.h"
#include "aes.h"

void print_block(const char *label, const uint8_t block[16]) {
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02X", block[i]);
        if (i % 4 == 3) printf(" ");
    }
    printf("\n");
}

int main(void) {
    // Example 16-byte key (AES-128)
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    // Example 16-byte plaintext
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    uint8_t ciphertext[16];
    uint8_t sbox[256];
    uint8_t round_keys[176];

    // Generate S-box
    initialize_aes_sbox(sbox);

    // Expand the key
    aes_key_expansion(key, round_keys, sbox);

    // Encrypt the block
    aes_encrypt_block(plaintext, ciphertext, round_keys, sbox);

    // Print results
    print_block("Plaintext ", plaintext);
    print_block("Ciphertext", ciphertext);

    return 0;
}
