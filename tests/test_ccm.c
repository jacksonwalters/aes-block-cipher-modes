#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ccm.h"
#include "aes_wrapper.h"
#include "test_ccm.h"

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int run_ccm_test(const char *test_name,
                        const uint8_t *key,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        const uint8_t *expected_ciphertext, size_t expected_ct_len,
                        size_t tag_len)
{
    printf("\n=== Testing %s ===\n", test_name);
    printf("Nonce length: %zu, AAD length: %zu, Plaintext length: %zu, Tag length: %zu\n",
           nonce_len, aad_len, plaintext_len, tag_len);

    /* Allocate buffer for ciphertext output */
    uint8_t *ciphertext = malloc(plaintext_len + tag_len);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    size_t ciphertext_len = 0;

    /* Encrypt - note parameter order matches ccm.c */
    int ret = ccm_encrypt(key,                    /* key_ctx */
                          aes_block_wrapper,      /* encrypt function */
                          nonce, nonce_len,       /* nonce, n */
                          aad, aad_len,           /* aad, aad_len */
                          plaintext, plaintext_len, /* plaintext, payload_len */
                          ciphertext, &ciphertext_len, /* ciphertext, ciphertext_len */
                          tag_len);                /* t */

    if (ret != 0) {
        fprintf(stderr, "[FAIL] %s: Encryption failed with error %d\n", test_name, ret);
        free(ciphertext);
        return 1;
    }

    if (ciphertext_len != expected_ct_len) {
        fprintf(stderr, "[FAIL] %s: Ciphertext length mismatch (got %zu, expected %zu)\n",
                test_name, ciphertext_len, expected_ct_len);
        free(ciphertext);
        return 1;
    }

    /* Compare ciphertext */
    if (memcmp(ciphertext, expected_ciphertext, expected_ct_len) != 0) {
        fprintf(stderr, "[FAIL] %s: Ciphertext mismatch\n", test_name);
        print_hex("Expected", expected_ciphertext, expected_ct_len);
        print_hex("Got     ", ciphertext, ciphertext_len);
        free(ciphertext);
        return 1;
    }

    printf("[PASS] Encryption matches expected ciphertext\n");

    /* Decrypt */
    uint8_t *decrypted = malloc(plaintext_len);
    if (!decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        free(ciphertext);
        return 1;
    }
    size_t decrypted_len = 0;

    ret = ccm_decrypt(key, aes_block_wrapper,
                      nonce, nonce_len,
                      aad, aad_len,
                      ciphertext, ciphertext_len,
                      decrypted, &decrypted_len,
                      tag_len);

    if (ret != 0) {
        fprintf(stderr, "[FAIL] %s: Decryption failed with error %d\n", test_name, ret);
        free(ciphertext);
        free(decrypted);
        return 1;
    }

    if (decrypted_len != plaintext_len) {
        fprintf(stderr, "[FAIL] %s: Decrypted length mismatch (got %zu, expected %zu)\n",
                test_name, decrypted_len, plaintext_len);
        free(ciphertext);
        free(decrypted);
        return 1;
    }

    /* Compare decrypted plaintext */
    if (memcmp(decrypted, plaintext, plaintext_len) != 0) {
        fprintf(stderr, "[FAIL] %s: Decrypted plaintext mismatch\n", test_name);
        print_hex("Expected", plaintext, plaintext_len);
        print_hex("Got     ", decrypted, decrypted_len);
        free(ciphertext);
        free(decrypted);
        return 1;
    }

    printf("[PASS] Decryption recovers original plaintext\n");

    free(ciphertext);
    free(decrypted);
    return 0;
}

int main(void)
{
    int failed = 0;

    printf("Running NIST SP 800-38C CCM Test Vectors\n");
    printf("==========================================\n");

    /* Test Example 1 */
    failed += run_ccm_test("Example 1",
                           CCM_KEY,
                           CCM_EX1_NONCE, CCM_EX1_NONCE_LEN,
                           CCM_EX1_AAD, CCM_EX1_AAD_LEN,
                           CCM_EX1_P, CCM_EX1_P_LEN,
                           CCM_EX1_C, CCM_EX1_C_LEN,
                           CCM_EX1_TAG_LEN);

    /* Test Example 2 */
    failed += run_ccm_test("Example 2",
                           CCM_KEY,
                           CCM_EX2_NONCE, CCM_EX2_NONCE_LEN,
                           CCM_EX2_AAD, CCM_EX2_AAD_LEN,
                           CCM_EX2_P, CCM_EX2_P_LEN,
                           CCM_EX2_C, CCM_EX2_C_LEN,
                           CCM_EX2_TAG_LEN);

    /* Test Example 3 */
    failed += run_ccm_test("Example 3",
                           CCM_KEY,
                           CCM_EX3_NONCE, CCM_EX3_NONCE_LEN,
                           CCM_EX3_AAD, CCM_EX3_AAD_LEN,
                           CCM_EX3_P, CCM_EX3_P_LEN,
                           CCM_EX3_C, CCM_EX3_C_LEN,
                           CCM_EX3_TAG_LEN);

    printf("\n==========================================\n");
    if (failed == 0) {
        printf("✅ All CCM tests PASSED\n");
    } else {
        printf("❌ %d test(s) FAILED\n", failed);
    }

    return failed;
}