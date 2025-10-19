#include <stdio.h>
#include <stdint.h>
#include "../include/sbox.h"
#include "../include/key_expansion_128.h"
#include "../include/aes_128.h"
#include <string.h>

#define BLOCK_SIZE 16

void print_block_hex(const uint8_t *block, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02X ", block[i]);
        if ((i & 0x0F) == 0x0F) printf("\n");
    }
}

void print_block_ascii(const uint8_t *block, int length) {
    for (int i = 0; i < length; i++) {
        if (block[i] >= 32 && block[i] <= 126) // printable ASCII
            printf("%c", block[i]);
        else
            printf(".");
    }
}

void print_sbox(void) {
    uint8_t sbox[256];  // allocate space for 256 uint8_t values

    initialize_aes_sbox(sbox);

    // Print the S-box
    for (int i = 0; i < 256; i++) {
        printf("%02X ", sbox[i]);
        if ((i & 0x0F) == 0x0F) printf("\n");
    }
}

int main(void) {
    uint8_t sbox[256];
    uint8_t round_keys[176];

    // Key (same as before)
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    // Example plaintext string
    const char *plaintext_str = "Hello, AES encryption in C! This string will be encrypted block-by-block.";

    // Calculate padded length (multiple of BLOCK_SIZE)
    size_t len = strlen(plaintext_str);
    size_t padded_len = ((len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;

    // Allocate buffers
    uint8_t plaintext[padded_len];
    uint8_t ciphertext[padded_len];
    uint8_t decrypted[padded_len];

    // Copy plaintext and pad with zeros
    memset(plaintext, 0, padded_len);
    memcpy(plaintext, plaintext_str, len);

    // Initialize S-box and expand keys
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(key, round_keys, sbox);

    // Encrypt block by block
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        aes128_encrypt_block(&plaintext[i], &ciphertext[i], round_keys, sbox);
    }

    // Decrypt block by block
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        aes128_decrypt_block(&ciphertext[i], &decrypted[i], round_keys, sbox);
    }

    // Print results
    printf("Original plaintext:\n%s\n\n", plaintext_str);

    printf("Encrypted (hex):\n");
    print_block_hex(ciphertext, (int)padded_len);
    printf("\n");

    printf("Decrypted text:\n");
    print_block_ascii(decrypted, (int)padded_len);
    printf("\n");

    return 0;
}

