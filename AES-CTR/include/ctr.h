#ifndef CTR_H
#define CTR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CTR_BLOCK_SIZE 16

/* block encrypt function type:
 * - in:  16-byte plaintext/block
 * - out: 16-byte output block (ciphertext / keystream block)
 * - rk:  pointer to key schedule/expanded key used by the block cipher
 */
typedef void (*block_encrypt_fn)(const uint8_t in[CTR_BLOCK_SIZE],
                                 uint8_t out[CTR_BLOCK_SIZE],
                                 const void *rk);

/* aes_ctr_crypt
 * - in: input buffer (plaintext for encrypt, ciphertext for decrypt)
 * - out: output buffer (ciphertext for encrypt, plaintext for decrypt)
 * - len: length in bytes (may be any non-negative length)
 * - counter: 16-byte initial counter block (will NOT be modified)
 * - encrypt: block encryption function (AES block encrypt)
 * - rk: pointer to expanded key / key schedule used by encrypt()
 *
 * Note: This function allocates a small internal buffer (16 bytes) for the
 * keystream block. It is not re-entrant in C sense only if encrypt() is not.
 *
 * The function implements CTR as defined in NIST SP 800-38A (Section 6.5)
 * using the counter layout: [nonce (left bytes) || counter (rightmost 32 bits)].
 * The increment function increments the rightmost 32-bit word as a big-endian
 * integer. Modify ctr_increment() in ctr.c if you need different layout.
 */
void aes_ctr_crypt(const uint8_t *in, uint8_t *out, size_t len,
                   const uint8_t counter[CTR_BLOCK_SIZE],
                   block_encrypt_fn encrypt, const void *rk);

/* helper: increment a 16-byte counter block in place (rightmost 32-bit BE) */
void ctr_increment(uint8_t counter[CTR_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* CTR_H */