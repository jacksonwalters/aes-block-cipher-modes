#include <stdio.h>
#include <string.h>
#include "ccm.h"
#include "aes_wrapper.h"
#include "test_ccm.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (len %zu): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int run_vector(const uint8_t *key,
                      const uint8_t *nonce, size_t n,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *pt, size_t pt_len,
                      const uint8_t *expected_ct, size_t ct_len,
                      size_t tag_len,
                      const char *name)
{
    uint8_t ciphertext[256] = {0};
    size_t ciphertext_len = 0;
    int success = 1;

    printf("--- %s ---\n", name);
    printf("Parameters: Nlen=%zu, Alen=%zu, Plen=%zu, Tlen=%zu\n", 
           n * 8, aad_len * 8, pt_len * 8, tag_len * 8);

    /* --- ENCRYPTION TEST --- */
    int ret = ccm_encrypt(
        key,
        aes_block_wrapper,
        nonce, n,
        aad, aad_len,
        pt, pt_len,
        ciphertext, &ciphertext_len,
        tag_len
    );

    if (ret != 0) {
        printf("[-] Encryption FAILED (code=%d)\n", ret);
        success = 0; goto cleanup;
    }

    if (ciphertext_len != ct_len) {
        printf("[-] Ciphertext length MISMATCH. Expected %zu, got %zu\n", ct_len, ciphertext_len);
        success = 0; goto cleanup;
    }
    
    if (memcmp(ciphertext, expected_ct, ct_len) != 0) {
        printf("[-] Ciphertext content MISMATCH\n");
        print_hex("    Expected C", expected_ct, ct_len);
        print_hex("    Actual C  ", ciphertext, ciphertext_len);
        success = 0; goto cleanup;
    }
    printf("[+] Encryption successful\n");

    /* --- DECRYPTION TEST --- */
    uint8_t decrypted[256] = {0};
    size_t decrypted_len = 0;

    ret = ccm_decrypt(
        key,
        aes_block_wrapper,
        nonce, n,
        aad, aad_len,
        ciphertext, ciphertext_len,
        decrypted, &decrypted_len,
        tag_len
    );

    if (ret != 0) {
        printf("[-] Decryption/Verification FAILED (code=%d)\n", ret);
        success = 0; goto cleanup;
    }

    if (decrypted_len != pt_len) {
        printf("[-] Decrypted plaintext length MISMATCH. Expected %zu, got %zu\n", pt_len, decrypted_len);
        success = 0; goto cleanup;
    }

    if (memcmp(decrypted, pt, pt_len) != 0) {
        printf("[-] Decrypted plaintext content MISMATCH\n");
        print_hex("    Expected P", pt, pt_len);
        print_hex("    Actual P  ", decrypted, decrypted_len);
        success = 0; goto cleanup;
    }
    printf("[+] Decryption/Verification successful\n");

cleanup:
    return success;
}

int main(void) {
    printf("===== Running bin/test_ccm (NIST SP 800-38C Appendix C) =====\n");

    int pass = 1;

    if (!run_vector(CCM_KEY,
                    CCM_EX1_NONCE, CCM_EX1_NONCE_LEN,
                    CCM_EX1_AAD, CCM_EX1_AAD_LEN,
                    CCM_EX1_P, CCM_EX1_P_LEN,
                    CCM_EX1_C, CCM_EX1_C_LEN,
                    CCM_EX1_TAG_LEN,
                    "CCM Example 1")) pass = 0;

    if (!run_vector(CCM_KEY,
                    CCM_EX2_NONCE, CCM_EX2_NONCE_LEN,
                    CCM_EX2_AAD, CCM_EX2_AAD_LEN,
                    CCM_EX2_P, CCM_EX2_P_LEN,
                    CCM_EX2_C, CCM_EX2_C_LEN,
                    CCM_EX2_TAG_LEN,
                    "CCM Example 2")) pass = 0;

    if (!run_vector(CCM_KEY,
                    CCM_EX3_NONCE, CCM_EX3_NONCE_LEN,
                    CCM_EX3_AAD, CCM_EX3_AAD_LEN,
                    CCM_EX3_P, CCM_EX3_P_LEN,
                    CCM_EX3_C, CCM_EX3_C_LEN,
                    CCM_EX3_TAG_LEN,
                    "CCM Example 3")) pass = 0;

    printf("===================================================\n");
    if (pass)
        printf("[+] CCM tests PASSED\n");
    else
        printf("[-] CCM tests FAILED\n");
    printf("===================================================\n");

    return pass ? 0 : 1;
}