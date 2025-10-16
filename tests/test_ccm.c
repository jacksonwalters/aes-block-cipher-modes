#include <stdio.h>
#include <string.h>
#include "ccm.h"
#include "aes_wrapper.h"
#include "aes_128.h"
#include "key_expansion_128.h"
#include "sbox.h"
#include "test_ccm.h"

static int run_vector(struct aes_ctx *ctx,
                      const uint8_t *nonce, size_t n,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *pt, size_t pt_len,
                      const uint8_t *expected_ct, size_t ct_len,
                      size_t tag_len)
{
    uint8_t ciphertext[256] = {0};
    size_t ciphertext_len = 0;

    int ret = ccm_encrypt(
        (const uint8_t *)ctx,   // pass pointer to aes_ctx
        aes_block_wrapper,
        nonce, n,
        aad, aad_len,
        pt, pt_len,
        ciphertext, &ciphertext_len,
        tag_len
    );

    if (ret != 0) { printf("[-] Encryption failed\n"); return 0; }

    if (ciphertext_len != ct_len || memcmp(ciphertext, expected_ct, ct_len) != 0) {
        printf("[-] Ciphertext mismatch\n"); return 0;
    }

    uint8_t decrypted[256] = {0};
    size_t decrypted_len = 0;

    ret = ccm_decrypt(
        (const uint8_t *)ctx,
        aes_block_wrapper,
        nonce, n,
        aad, aad_len,
        ciphertext, ciphertext_len,
        decrypted, &decrypted_len,
        tag_len
    );

    if (ret != 0) { printf("[-] Decryption failed\n"); return 0; }

    if (decrypted_len != pt_len || memcmp(decrypted, pt, pt_len) != 0) {
        printf("[-] Plaintext mismatch\n"); return 0;
    }

    return 1;
}

int main(void)
{
    uint8_t round_keys[176];
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion(CCM_KEY, round_keys, sbox);

    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16};

    int pass = 1;

    printf("[TEST] CCM Example 1\n");
    if (!run_vector(&ctx,
                    CCM_EX1_NONCE, CCM_EX1_NONCE_LEN,
                    CCM_EX1_AAD, CCM_EX1_AAD_LEN,
                    CCM_EX1_P, CCM_EX1_P_LEN,
                    CCM_EX1_C, CCM_EX1_C_LEN,
                    CCM_EX1_TAG_LEN)) pass = 0;

    printf("[TEST] CCM Example 2\n");
    if (!run_vector(&ctx,
                    CCM_EX2_NONCE, CCM_EX2_NONCE_LEN,
                    CCM_EX2_AAD, CCM_EX2_AAD_LEN,
                    CCM_EX2_P, CCM_EX2_P_LEN,
                    CCM_EX2_C, CCM_EX2_C_LEN,
                    CCM_EX2_TAG_LEN)) pass = 0;

    printf("[TEST] CCM Example 3\n");
    if (!run_vector(&ctx,
                    CCM_EX3_NONCE, CCM_EX3_NONCE_LEN,
                    CCM_EX3_AAD, CCM_EX3_AAD_LEN,
                    CCM_EX3_P, CCM_EX3_P_LEN,
                    CCM_EX3_C, CCM_EX3_C_LEN,
                    CCM_EX3_TAG_LEN)) pass = 0;

    if (pass)
        printf("[+] CCM tests PASSED\n");
    else
        printf("[-] CCM tests FAILED\n");

    return pass ? 0 : 1;
}
