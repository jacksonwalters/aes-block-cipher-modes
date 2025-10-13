#ifndef CBC_H
#define CBC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK 16

/* encryption / decryption function types (adapter style):
 * encrypt_fn: encrypt one 16-byte block
 * decrypt_fn: decrypt one 16-byte block
 *
 * Both follow the pattern:
 *    void fn(const uint8_t in[16], uint8_t out[16], const void *ctx);
 * where ctx is a pointer to the AES context (round keys + sbox).
 */
typedef void (*encrypt_block_fn)(const uint8_t in[AES_BLOCK],
                                 uint8_t out[AES_BLOCK],
                                 const void *ctx);

typedef void (*decrypt_block_fn)(const uint8_t in[AES_BLOCK],
                                 uint8_t out[AES_BLOCK],
                                 const void *ctx);

/* AES-CBC encrypt: pads with PKCS#7 to a multiple of 16 bytes.
 * - in: plaintext
 * - in_len: plaintext length
 * - out: buffer to receive ciphertext; must be at least ((in_len / 16) + 1) * 16 bytes
 * - out_len: pointer to store resulting ciphertext length
 * - iv: 16-byte initialization vector
 * - encrypt: block encrypt function
 * - ctx: pointer to AES context (round keys + sbox)
 */
int aes_cbc_encrypt(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len,
                    const uint8_t iv[AES_BLOCK],
                    encrypt_block_fn encrypt, const void *ctx);

/* AES-CBC decrypt:
 * - in: ciphertext (multiple of 16 bytes)
 * - in_len: ciphertext length (must be multiple of 16)
 * - out: buffer to receive plaintext; must be at least in_len bytes
 * - out_len: pointer to store resulting plaintext length
 * - iv: 16-byte IV used during encryption
 * - decrypt: block decrypt function
 * - ctx: pointer to AES context
 *
 * Returns 0 on success, non-zero on failure (e.g., invalid padding).
 */
int aes_cbc_decrypt(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len,
                    const uint8_t iv[AES_BLOCK],
                    decrypt_block_fn decrypt, const void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CBC_H */