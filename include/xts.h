#ifndef XTS_H
#define XTS_H

#include <stdint.h>
#include <stddef.h>

/*
 * XTS-AES implementation (API header)
 *
 * Notes:
 *  - This implementation encodes the 64-bit data_unit number as a 128-bit
 *    big-endian quantity placed in the low-order 8 bytes of the 16-byte
 *    tweak input to AES(K2, T). Concretely:
 *
 *      tweak_plain[0..7]  = 0x00 (high-order 64 bits)
 *      tweak_plain[8..15] = data_unit (big-endian: MSB at index 8)
 *
 *    This choice ensures the MSB of the 128-bit tweak is at tweak[0],
 *    which matches the multiply_by_x helper (MSB-first).
 *
 *  - The aes block function type matches your `aes_block_wrapper`:
 *      void fn(const uint8_t in[16], uint8_t out[16], const void *ctx);
 *
 *  - This implementation enforces no particular maximum on the data unit
 *    length; the caller must ensure the NIST-recommended limit (<= 2^20 blocks)
 *    if conformance is required. See NIST SP 800-38E (ordering convention for
 *    ciphertext stealing). :contentReference[oaicite:1]{index=1}
 */

/* AES block function signature type (matches aes_wrapper) */
typedef void (*aes_block_fn)(const uint8_t in[16], uint8_t out[16], const void *ctx);

/* Return codes */
#define XTS_OK           0
#define XTS_ERR_INVALID  1
#define XTS_ERR_ARG      2

/*
 * xts_encrypt / xts_decrypt
 *
 * - Requires pt_len >= 16 (at least one full block). Returns XTS_ERR_INVALID otherwise.
 * - Handles ciphertext stealing automatically for non-multiple-of-16 lengths.
 * - aes_enc: block encrypt function using key K1 (data encryption)
 * - aes_tweak: block encrypt function using key K2 (tweak computation)
 * - key1_ctx, key2_ctx: pointers to contexts for aes_enc and aes_tweak (passed
 *                       through unchanged to the functions)
 * - data_unit: 64-bit data unit number (sector number). See notes above about encoding.
 * - plaintext: input buffer (may be any length >= 1)
 * - pt_len: plaintext length in bytes
 * - ciphertext: output buffer (must be at least pt_len bytes)
 *
 * Returns XTS_OK on success, non-zero otherwise.
 */
int xts_encrypt(aes_block_fn aes_enc, const void *key1_ctx,
                aes_block_fn aes_tweak, const void *key2_ctx,
                uint64_t data_unit,
                const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext);

int xts_decrypt(aes_block_fn aes_dec, const void *key1_ctx,
                aes_block_fn aes_tweak, const void *key2_ctx,
                uint64_t data_unit,
                const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext);

#endif /* XTS_H */
