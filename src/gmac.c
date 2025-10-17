#include "gmac.h"
#include <string.h>

/* Initialize GMAC context */
int gmac_init(struct gmac_ctx *ctx,
              const uint8_t *key, size_t key_len,
              const uint8_t *iv, size_t iv_len) {
    return gcm_init(&ctx->gcm, key, key_len, iv, iv_len);
}

/* Compute GMAC tag (wraps GCM with empty plaintext) */
void gmac_compute(struct gmac_ctx *ctx,
                  const uint8_t *aad, size_t aad_len,
                  uint8_t *tag, size_t tag_len) {
    // GMAC is just GCM with empty plaintext (len=0)
    // We can pass NULL for both plaintext and ciphertext since len=0
    gcm_encrypt(&ctx->gcm, NULL, 0, aad, aad_len, NULL, tag, tag_len);
}