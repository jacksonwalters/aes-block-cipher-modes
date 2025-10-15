#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../include/aes_256.h"
#include "../include/key_expansion_256.h"
#include "../include/sbox.h"
#include "aes_defs.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i & 0x0F) == 0x0F) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

int main() {
    // 32-byte AES-256 key (example)
    uint8_t key[AES256_KEY_SIZE] = {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
        0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
        0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    };

    uint8_t sbox[256];
    initialize_aes_sbox(sbox);

    uint8_t expanded_key[AES256_EXPANDED_KEY_SIZE];
    aes_key_expansion_256(key, expanded_key, sbox);

    const char *plaintext_str = "The quick brown fox jumps over the lazy dog";

    // Pad plaintext to multiple of block size with zeros
    size_t len = strlen(plaintext_str);
    size_t padded_len = ((len + AES256_BLOCK_SIZE - 1) / AES256_BLOCK_SIZE) * AES256_BLOCK_SIZE;

    uint8_t *plaintext = calloc(padded_len, sizeof(uint8_t));
    memcpy(plaintext, plaintext_str, len);

    uint8_t *ciphertext = malloc(padded_len);
    uint8_t *decrypted = malloc(padded_len);

    printf("Plaintext:\n%s\n\n", plaintext_str);

    // Encrypt block by block
    for (size_t i = 0; i < padded_len; i += AES256_BLOCK_SIZE) {
        aes256_encrypt_block(plaintext + i, ciphertext + i, expanded_key, sbox);
    }

    printf("Ciphertext (hex):\n");
    print_hex(ciphertext, padded_len);
    printf("\n");

    // Decrypt block by block
    for (size_t i = 0; i < padded_len; i += AES256_BLOCK_SIZE) {
        aes256_decrypt_block(ciphertext + i, decrypted + i, expanded_key, sbox);
    }

    printf("Decrypted text:\n%s\n", decrypted);

    free(plaintext);
    free(ciphertext);
    free(decrypted);

    printf("\nS-box (hex):\n");
    print_hex(sbox, 256);

    return 0;
}


