#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/ccm.h"
#include "../include/aes_wrapper.h"
#include "../include/aes_128.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

// Helper function for printing hex buffers
static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    if (label) printf("%s:", label);
    for (size_t i = 0; i < len; i++)
        printf(" %02x", buf[i]);
    printf("\n");
}

// NIST CCM test vectors (Appendix C)
typedef struct {
    const char *name;
    const uint8_t *nonce;
    size_t n_len;
    const uint8_t *aad;
    size_t ad_len;
    const uint8_t *plaintext;
    size_t pt_len;
    const uint8_t *exp_cipher;
    const uint8_t *exp_tag;
    size_t tag_len;
} ccm_test_t;

int main(void) {
    // AES-128 key
    const uint8_t key[16] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F
    };

    // AES context setup
    uint8_t round_keys[176];
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox };

    // Test vectors (exact from NIST Appendix C)
    static const uint8_t nonce1[7] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16};
    static const uint8_t aad1[8]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
    static const uint8_t pt1[4]    = {0x20,0x21,0x22,0x23};
    static const uint8_t ct1[8]    = {0x71,0x62,0x01,0x5B,0x4D,0xAC,0x25,0x5D};
    static const uint8_t tag1[4]   = {0x60,0x84,0x34,0x1B};

    const ccm_test_t tests[] = {
        {"CCM Example 1", nonce1, sizeof(nonce1), aad1, sizeof(aad1), pt1, sizeof(pt1), ct1, tag1, sizeof(tag1)}
    };

    int fail = 0;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        uint8_t ciphertext[64] = {0};
        uint8_t tag[16] = {0};
        uint8_t decrypted[64] = {0};

        printf("\n--- %s ---\n", tests[i].name);

        aes_ccm_encrypt(tests[i].plaintext, tests[i].pt_len,
                        tests[i].aad, tests[i].ad_len,
                        tests[i].nonce, tests[i].n_len,
                        tests[i].tag_len,
                        ciphertext, tag,
                        &ctx);

        if (memcmp(ciphertext, tests[i].exp_cipher, tests[i].pt_len) != 0) {
            printf("[-] %s ciphertext FAILED\n", tests[i].name);
            print_hex("Expected", tests[i].exp_cipher, tests[i].pt_len);
            print_hex("Actual  ", ciphertext, tests[i].pt_len);
            fail = 1;
        }

        if (memcmp(tag, tests[i].exp_tag, tests[i].tag_len) != 0) {
            printf("[-] %s tag FAILED\n", tests[i].name);
            print_hex("Expected", tests[i].exp_tag, tests[i].tag_len);
            print_hex("Actual  ", tag, tests[i].tag_len);
            fail = 1;
        }

        if (aes_ccm_decrypt(tests[i].exp_cipher, tests[i].pt_len,
                            tests[i].aad, tests[i].ad_len,
                            tests[i].nonce, tests[i].n_len,
                            tests[i].tag_len,
                            tests[i].exp_tag,
                            decrypted,
                            &ctx) != 0 ||
            memcmp(decrypted, tests[i].plaintext, tests[i].pt_len) != 0) {
            printf("[-] %s decryption FAILED\n", tests[i].name);
            fail = 1;
        } else {
            printf("[+] %s encryption and decryption OK\n", tests[i].name);
        }
    }

    return fail;
}
