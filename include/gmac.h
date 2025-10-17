#ifndef GMAC_H
#define GMAC_H

#include <stdint.h>
#include <stddef.h>
#include "gcm.h"   // Uses your existing GCM context and functions

struct gmac_ctx {
    struct gcm_ctx gcm;
};

/* Initialize GMAC context with key and IV */
int gmac_init(struct gmac_ctx *ctx,
              const uint8_t *key, size_t key_len,
              const uint8_t *iv, size_t iv_len);

/* Compute GMAC tag over AAD (plaintext is always empty) */
void gmac_compute(struct gmac_ctx *ctx,
                  const uint8_t *aad, size_t aad_len,
                  uint8_t *tag, size_t tag_len);

#endif /* GMAC_H */
