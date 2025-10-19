#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/cfb.h"
#include "../include/aes_wrapper.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

int main(void) {
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t plaintext[] = "CFB mode test message";
    size_t len = strlen((char*)plaintext);

    uint8_t ciphertext[64] = {0};
    uint8_t decrypted[64] = {0};

    uint8_t round_keys[176];
    uint8_t sbox[256];

    //initialize the sbox
    initialize_aes_sbox(sbox);
    
    // Expand the key for encryption
    aes_key_expansion_128(key, round_keys, sbox);

    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16};

    aes_cfb_encrypt(plaintext, ciphertext, len, iv, &ctx);
    aes_cfb_decrypt(ciphertext, decrypted, len, iv, &ctx);

    if (memcmp(plaintext, decrypted, len) == 0) {
        printf("[+] CFB test passed: %s\n", decrypted);
        return 0;
    } else {
        printf("[-] CFB test failed!\n");
        return 1;
    }
}
