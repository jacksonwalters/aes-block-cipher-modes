#ifndef CCM_H
#define CCM_H

#include <stddef.h>
#include <stdint.h>
#include "aes_wrapper.h"  // AES context

#ifdef __cplusplus
extern "C" {
#endif

/**
 * AES-CCM Encryption
 * @param plaintext  Input plaintext
 * @param pt_len     Length of plaintext
 * @param associated Associated data (can be NULL)
 * @param ad_len     Length of associated data
 * @param nonce      Nonce
 * @param n_len      Nonce length (7–13 bytes)
 * @param tag_len    Length of authentication tag (4,6,8,10,12,14,16)
 * @param ciphertext Output ciphertext (same length as plaintext)
 * @param tag        Output authentication tag
 * @param ctx        AES context
 */
void aes_ccm_encrypt(const uint8_t *plaintext, size_t pt_len,
                     const uint8_t *associated, size_t ad_len,
                     const uint8_t *nonce, size_t n_len,
                     size_t tag_len,
                     uint8_t *ciphertext, uint8_t *tag,
                     const struct aes_ctx *ctx);

/**
 * AES-CCM Decryption
 * Returns 0 if authentication passes, 1 if it fails
 */
int aes_ccm_decrypt(const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *associated, size_t ad_len,
                    const uint8_t *nonce, size_t n_len,
                    size_t tag_len,
                    const uint8_t *tag,
                    uint8_t *plaintext,
                    const struct aes_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif // CCM_H
