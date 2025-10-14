#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/aes_128.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

int main(void) {
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t round_keys[176];
    uint8_t sbox[256];
    uint8_t block[16] = "Hello AES Block!";
    uint8_t enc[16], dec[16];

    initialize_aes_sbox(sbox);
    aes_key_expansion(key, round_keys, sbox);

    aes_encrypt_block(block, enc, round_keys, sbox);
    aes_decrypt_block(enc, dec, round_keys, sbox);

    if(memcmp(block, dec, 16) == 0) {
        printf("AES core round-trip OK\n");
    } else {
        printf("AES core FAILED\n");
    }

    printf("Plaintext:  %s\n", block);
    printf("Ciphertext: ");
    for(int i=0;i<16;i++) printf("%02x", enc[i]);
    printf("\n");

    return 0;
}
