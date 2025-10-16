#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../include/cbc.h"
#include "../include/aes_wrapper.h"
#include "../include/aes_128.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

/* helper to print hex */
static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x", buf[i]);
    printf("\n");
}

int main(void) {
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t round_keys[176];
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion(key, round_keys, sbox);

    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16};

    const uint8_t pt[] = "Hello AES-CBC, this is 37 bytes long..";
    size_t pt_len = strlen((const char*)pt);

    uint8_t ciphertext[256] = {0};
    size_t ct_len = 0;
    uint8_t recovered[256] = {0};
    size_t rec_len = 0;

    uint8_t iv[16] = {0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f};

    if (aes_cbc_encrypt(pt, pt_len, ciphertext, &ct_len, iv, aes_block_wrapper, &ctx) != 0) {
        fprintf(stderr, "CBC encrypt failed\n");
        return 2;
    }

    if (aes_cbc_decrypt(ciphertext, ct_len, recovered, &rec_len, iv, aes_block_wrapper_dec, &ctx) != 0) {
        fprintf(stderr, "CBC decrypt failed\n");
        return 3;
    }

    if (rec_len != pt_len || memcmp(pt, recovered, pt_len) != 0) {
        fprintf(stderr, "CBC round-trip FAILED\n");
        return 4;
    }

    printf("CBC round-trip OK — plaintext recovered correctly.\n");
    printf("Plaintext: '%s'\n", (char*)pt);
    printf("Ciphertext (hex): ");
    print_hex(ciphertext, ct_len);

    return 0;
}
