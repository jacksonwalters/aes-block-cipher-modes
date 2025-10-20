#ifndef KW_H
#define KW_H

#include <stddef.h>
#include <stdint.h>
#include "aes_wrapper.h"

/**
 * Wrap a plaintext key using AES Key Wrap (RFC 3394 / NIST SP 800-38F).
 */
int kw_wrap(const uint8_t *plaintext, size_t plen,
            uint8_t *ciphertext, const struct aes_ctx *ctx);

/**
 * Unwrap a wrapped key using AES Key Wrap.
 */
int kw_unwrap(const uint8_t *ciphertext, size_t clen,
              uint8_t *plaintext, const struct aes_ctx *ctx);

#endif
