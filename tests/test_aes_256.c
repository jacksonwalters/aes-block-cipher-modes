#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/aes_256.h"
#include "../include/key_expansion_256.h"
#include "../include/sbox.h"

int main(void) {
    // 256-bit key (32 bytes)
    uint8_t key[32] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    };
    uint8_t round_keys[240];  // 15 round keys * 16 bytes
    uint8_t sbox[256];
    uint8_t block[16] = "Hello AES Block!";
    uint8_t enc[16], dec[16];

    initialize_aes_sbox(sbox);
    aes_key_expansion_256(key, round_keys, sbox);

    printf("=== AES-256 Test ===\n");
    printf("Key length: 256 bits (32 bytes)\n");
    printf("Rounds: 14\n\n");

    aes256_encrypt_block(block, enc, round_keys, sbox);
    aes256_decrypt_block(enc, dec, round_keys, sbox);

    if(memcmp(block, dec, 16) == 0) {
        printf("AES-256 core round-trip OK\n");
    } else {
        printf("AES-256 core FAILED\n");
        return 1;
    }

    printf("\nPlaintext:  %s\n", block);
    printf("Ciphertext: ");
    for(int i=0; i<16; i++) printf("%02x", enc[i]);
    printf("\n");
    printf("Decrypted:  %s\n", dec);

    // Test with known NIST test vector for AES-256
    printf("\n=== NIST Test Vector ===\n");
    uint8_t nist_key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    uint8_t nist_pt[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t nist_expected_ct[16] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
    };
    uint8_t nist_ct[16], nist_dec[16];

    aes_key_expansion_256(nist_key, round_keys, sbox);
    aes256_encrypt_block(nist_pt, nist_ct, round_keys, sbox);
    aes256_decrypt_block(nist_ct, nist_dec, round_keys, sbox);

    printf("Expected CT: ");
    for(int i=0; i<16; i++) printf("%02x", nist_expected_ct[i]);
    printf("\nComputed CT: ");
    for(int i=0; i<16; i++) printf("%02x", nist_ct[i]);
    printf("\n");

    if(memcmp(nist_ct, nist_expected_ct, 16) == 0) {
        printf("NIST test vector PASSED\n");
    } else {
        printf("NIST test vector FAILED\n");
        return 1;
    }

    if(memcmp(nist_pt, nist_dec, 16) == 0) {
        printf("NIST decryption PASSED\n");
    } else {
        printf("NIST decryption FAILED\n");
        return 1;
    }

    printf("\n=== All AES-256 tests passed! ===\n");
    return 0;
}