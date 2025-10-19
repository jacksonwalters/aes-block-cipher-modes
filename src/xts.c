#include "xts.h"
#include <string.h>

/* -------------------------------------------------------------------------*/
/* local helpers */

/* XOR 16 bytes: out = a ^ b */
static inline void xor16(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
    for (int i = 0; i < 16; ++i) out[i] = a[i] ^ b[i];
}

/*
 * multiply_by_x: multiply 128-bit tweak (MSB in byte 0) by x in GF(2^128)
 * Reduction polynomial: x^128 + x^7 + x^2 + x + 1 -> reduction constant 0x87
 */
static void multiply_by_x(uint8_t tweak[16]) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t next_carry = (tweak[i] & 0x80) ? 1 : 0;
        tweak[i] = (uint8_t)((tweak[i] << 1) | carry);
        carry = next_carry;
    }
    if (carry) tweak[15] ^= 0x87;
}

/*
 * encode_data_unit_be64: places 64-bit data_unit into tweak_plain[16] as a
 * 128-bit big-endian integer with high 64 bits zero and low 64 bits = data_unit.
 */
static void encode_data_unit_be64(uint8_t tweak_plain[16], uint64_t data_unit) {
    memset(tweak_plain, 0, 8);
    for (int i = 0; i < 8; ++i) {
        tweak_plain[8 + 7 - i] = (uint8_t)(data_unit & 0xFF);
        data_unit >>= 8;
    }
}

/* -------------------------------------------------------------------------*/
/* XTS encryption */

int xts_encrypt(aes_block_fn aes_enc, const void *key1_ctx,
                aes_block_fn aes_tweak, const void *key2_ctx,
                uint64_t data_unit,
                const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext)
{
    if (!aes_enc || !aes_tweak || !plaintext || !ciphertext) return XTS_ERR_ARG;
    if (pt_len < 16 || pt_len % 16 != 0) return XTS_ERR_INVALID;

    size_t n_blocks = pt_len / 16;

    uint8_t tweak[16], tweak_plain[16];
    encode_data_unit_be64(tweak_plain, data_unit);
    aes_tweak(tweak_plain, tweak, key2_ctx);

    for (size_t i = 0; i < n_blocks; ++i) {
        uint8_t tmp[16], out[16];
        xor16(plaintext + i*16, tweak, tmp);
        aes_enc(tmp, out, key1_ctx);
        xor16(out, tweak, ciphertext + i*16);
        multiply_by_x(tweak);
    }

    return XTS_OK;
}

/* -------------------------------------------------------------------------*/
/* XTS decryption */

int xts_decrypt(aes_block_fn aes_dec, const void *key1_ctx,
                aes_block_fn aes_tweak, const void *key2_ctx,
                uint64_t data_unit,
                const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext)
{
    if (!aes_dec || !aes_tweak || !plaintext || !ciphertext) return XTS_ERR_ARG;
    if (ct_len < 16 || ct_len % 16 != 0) return XTS_ERR_INVALID;

    size_t n_blocks = ct_len / 16;

    uint8_t tweak[16], tweak_plain[16];
    encode_data_unit_be64(tweak_plain, data_unit);
    aes_tweak(tweak_plain, tweak, key2_ctx);

    for (size_t i = 0; i < n_blocks; ++i) {
        uint8_t tmp[16], out[16];
        xor16(ciphertext + i*16, tweak, tmp);
        aes_dec(tmp, out, key1_ctx);
        xor16(out, tweak, plaintext + i*16);
        multiply_by_x(tweak);
    }

    return XTS_OK;
}
