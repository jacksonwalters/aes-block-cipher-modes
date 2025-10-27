#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../include/ecb.h"
#include "../include/aes_wrapper.h"
#include "../include/aes_128.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"
#include "../include/padding.h"

static int test_nist_vector(void) {
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
    aes_key_expansion_128(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16 };

    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};

    aes_ecb_encrypt(plaintext, ciphertext, 16, &ctx);
    aes_ecb_decrypt(ciphertext, decrypted, 16, &ctx);

    if (memcmp(ciphertext, expected_ciphertext, 16) != 0) return 1;
    if (memcmp(decrypted, plaintext, 16) != 0) return 2;
    return 0;
}

static int test_partial_block(void) {
    const uint8_t key[16] = {0};
    uint8_t round_keys[176], sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16 };

    uint8_t plaintext[5] = {1,2,3,4,5};
    uint8_t *cipher = NULL, *plain = NULL;
    size_t cipher_len = 0, plain_len = 0;

    if (aes_ecb_encrypt_padded(plaintext, 5, &ctx, &cipher, &cipher_len) != 0) return 1;
    if (aes_ecb_decrypt_padded(cipher, cipher_len, &ctx, &plain, &plain_len) != 0) return 2;

    if (plain_len != 5) return 3;
    if (memcmp(plain, plaintext, 5) != 0) return 4;

    free(cipher);
    free(plain);
    return 0;
}

static int test_empty(void) {
    const uint8_t key[16] = {0};
    uint8_t round_keys[176], sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16 };

    uint8_t *cipher = NULL, *plain = NULL;
    size_t cipher_len = 0, plain_len = 0;

    if (aes_ecb_encrypt_padded(NULL, 0, &ctx, &cipher, &cipher_len) != 0) return 1;
    if (aes_ecb_decrypt_padded(cipher, cipher_len, &ctx, &plain, &plain_len) != 0) return 2;

    if (plain_len != 0) return 3;

    free(cipher);
    free(plain);
    return 0;
}

int main(void) {
    if (test_nist_vector() != 0) { fprintf(stderr, "NIST ECB test FAILED\n"); return 1; }
    if (test_partial_block() != 0) { fprintf(stderr, "Partial-block ECB test FAILED\n"); return 2; }
    if (test_empty() != 0) { fprintf(stderr, "Empty ECB test FAILED\n"); return 3; }

    printf("All ECB tests passed.\n");
    return 0;
}
