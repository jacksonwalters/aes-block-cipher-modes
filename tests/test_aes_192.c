#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/aes_192.h"
#include "../include/key_expansion_192.h"
#include "../include/sbox.h"

int main(void) {
    // 192-bit key (24 bytes)
    uint8_t key[24] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23};
    uint8_t round_keys[208];  // 13 round keys * 16 bytes
    uint8_t sbox[256];
    uint8_t block[16] = "Hello AES Block!";
    uint8_t enc[16], dec[16];

    initialize_aes_sbox(sbox);
    aes_key_expansion_192(key, round_keys, sbox);

    printf("=== AES-192 Test ===\n");
    printf("Key length: 192 bits (24 bytes)\n");
    printf("Rounds: 12\n\n");

    aes192_encrypt_block(block, enc, round_keys, sbox);
    aes192_decrypt_block(enc, dec, round_keys, sbox);

    if(memcmp(block, dec, 16) == 0) {
        printf("✓ AES-192 core round-trip OK\n");
    } else {
        printf("✗ AES-192 core FAILED\n");
        return 1;
    }

    printf("\nPlaintext:  %s\n", block);
    printf("Ciphertext: ");
    for(int i=0; i<16; i++) printf("%02x", enc[i]);
    printf("\n");
    printf("Decrypted:  %s\n", dec);

    // Test with known NIST test vector for AES-192
    printf("\n=== NIST Test Vector ===\n");
    uint8_t nist_key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    uint8_t nist_pt[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t nist_expected_ct[16] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc
    };
    uint8_t nist_ct[16], nist_dec[16];

    aes_key_expansion_192(nist_key, round_keys, sbox);
    aes192_encrypt_block(nist_pt, nist_ct, round_keys, sbox);
    aes192_decrypt_block(nist_ct, nist_dec, round_keys, sbox);

    printf("Expected CT: ");
    for(int i=0; i<16; i++) printf("%02x", nist_expected_ct[i]);
    printf("\nComputed CT: ");
    for(int i=0; i<16; i++) printf("%02x", nist_ct[i]);
    printf("\n");

    if(memcmp(nist_ct, nist_expected_ct, 16) == 0) {
        printf("✓ NIST test vector PASSED\n");
    } else {
        printf("✗ NIST test vector FAILED\n");
        return 1;
    }

    if(memcmp(nist_pt, nist_dec, 16) == 0) {
        printf("✓ NIST decryption PASSED\n");
    } else {
        printf("✗ NIST decryption FAILED\n");
        return 1;
    }

    printf("\n=== All AES-192 tests passed! ===\n");
    return 0;
}