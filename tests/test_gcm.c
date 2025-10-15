#include <stdio.h>
#include <string.h>
#include "gcm.h"
#include "test_gcm.h"

int main(void) {
    struct gcm_ctx ctx;
    uint8_t ciphertext[sizeof(gcm_tv_pt_128)];
    uint8_t tag[16];
    uint8_t decrypted[sizeof(gcm_tv_pt_128)];

    gcm_init(&ctx, gcm_tv_key_128, sizeof(gcm_tv_key_128),
                  gcm_tv_iv_128, sizeof(gcm_tv_iv_128));

    gcm_encrypt(&ctx, gcm_tv_pt_128, sizeof(gcm_tv_pt_128),
                gcm_tv_aad_128, sizeof(gcm_tv_aad_128),
                ciphertext, tag, sizeof(tag));

    /* Verify ciphertext and tag */
    if (memcmp(ciphertext, gcm_tv_ct_128, sizeof(ciphertext)) != 0) {
        printf("Ciphertext mismatch!\n");
        return 1;
    }
    if (memcmp(tag, gcm_tv_tag_128, sizeof(tag)) != 0) {
        printf("Tag mismatch!\n");
        return 1;
    }
    printf("Encryption test passed.\n");

    /* Decrypt and verify */
    if (gcm_decrypt(&ctx, ciphertext, sizeof(ciphertext),
                    gcm_tv_aad_128, sizeof(gcm_tv_aad_128),
                    tag, sizeof(tag), decrypted) != 0) {
        printf("Decryption failed: tag mismatch\n");
        return 1;
    }
    if (memcmp(decrypted, gcm_tv_pt_128, sizeof(decrypted)) != 0) {
        printf("Decrypted plaintext mismatch!\n");
        return 1;
    }
    printf("Decryption test passed.\n");

    return 0;
}