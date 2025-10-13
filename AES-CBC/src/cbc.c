#include "cbc.h"
#include <string.h>
#include <stdlib.h>

/* PKCS#7 padding helper: returns number of padding bytes appended (1..16) */
static size_t pkcs7_pad(const uint8_t *in, size_t in_len, uint8_t *out) {
    size_t pad_len = AES_BLOCK - (in_len % AES_BLOCK);
    if (pad_len == 0) pad_len = AES_BLOCK;
    /* copy input */
    memcpy(out, in, in_len);
    /* append pad bytes */
    for (size_t i = 0; i < pad_len; ++i) out[in_len + i] = (uint8_t)pad_len;
    return pad_len;
}

/* remove PKCS#7 pad; returns 0 on success and sets *out_len to unpadded length.
 * Returns non-zero on invalid padding.
 */
static int pkcs7_unpad(uint8_t *buf, size_t buf_len, size_t *out_len) {
    if (buf_len == 0 || (buf_len % AES_BLOCK) != 0) return -1;
    uint8_t pad = buf[buf_len - 1];
    if (pad == 0 || pad > AES_BLOCK) return -2;
    /* check that last pad bytes equal pad */
    for (size_t i = 0; i < pad; ++i) {
        if (buf[buf_len - 1 - i] != pad) return -3;
    }
    *out_len = buf_len - pad;
    return 0;
}

/* XOR helper */
static inline void xor_block(uint8_t out[AES_BLOCK], const uint8_t a[AES_BLOCK], const uint8_t b[AES_BLOCK]) {
    for (int i = 0; i < AES_BLOCK; ++i) out[i] = a[i] ^ b[i];
}

int aes_cbc_encrypt(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len,
                    const uint8_t iv[AES_BLOCK],
                    encrypt_block_fn encrypt, const void *ctx)
{
    if (!in || !out || !out_len || !iv || !encrypt) return -1;

    /* padded buffer size = ceil(in_len/16)*16 + 16 (if in_len %16 ==0, add a full block) */
    size_t padded_len = ((in_len + AES_BLOCK - 1) / AES_BLOCK) * AES_BLOCK;
    if (padded_len == in_len) padded_len += AES_BLOCK;

    uint8_t *buf = (uint8_t*)malloc(padded_len);
    if (!buf) return -2;

    /* create padded plaintext in buf */
    size_t pad_len = pkcs7_pad(in, in_len, buf);
    (void)pad_len; /* padded_len equals in_len + pad_len */

    uint8_t prev[AES_BLOCK];
    memcpy(prev, iv, AES_BLOCK);

    for (size_t off = 0; off < padded_len; off += AES_BLOCK) {
        uint8_t block[AES_BLOCK];
        xor_block(block, buf + off, prev);
        encrypt(block, out + off, ctx);
        /* new prev = ciphertext block */
        memcpy(prev, out + off, AES_BLOCK);
    }

    *out_len = padded_len;
    /* wipe sensitive buffer */
    memset(buf, 0, padded_len);
    free(buf);
    memset(prev, 0, AES_BLOCK);
    return 0;
}

int aes_cbc_decrypt(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len,
                    const uint8_t iv[AES_BLOCK],
                    decrypt_block_fn decrypt, const void *ctx)
{
    if (!in || !out || !out_len || !iv || !decrypt) return -1;
    if ((in_len % AES_BLOCK) != 0) return -2;

    uint8_t prev[AES_BLOCK];
    memcpy(prev, iv, AES_BLOCK);

    for (size_t off = 0; off < in_len; off += AES_BLOCK) {
        uint8_t tmp[AES_BLOCK];
        decrypt(in + off, tmp, ctx); /* tmp = AES_DEC(Ci) */
        xor_block(out + off, tmp, prev); /* plaintext block = tmp XOR prev */
        memcpy(prev, in + off, AES_BLOCK);
    }

    /* unpad in-place on out */
    size_t unpadded_len = 0;
    int r = pkcs7_unpad(out, in_len, &unpadded_len);
    if (r != 0) {
        /* wipe and return error */
        memset(out, 0, in_len);
        memset(prev, 0, AES_BLOCK);
        return -3;
    }

    *out_len = unpadded_len;
    memset(prev, 0, AES_BLOCK);
    return 0;
}
