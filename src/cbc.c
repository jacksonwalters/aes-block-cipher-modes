#include "cbc.h"
#include "padding.h"
#include <string.h>
#include <stdlib.h>

/* ===============================
 *  Helper
 * =============================== */
static inline void xor_block(uint8_t out[AES_BLOCK],
                             const uint8_t a[AES_BLOCK],
                             const uint8_t b[AES_BLOCK])
{
    for (int i = 0; i < AES_BLOCK; ++i)
        out[i] = a[i] ^ b[i];
}

/* ===============================
 *  Core CBC (unpadded)
 * =============================== */
int aes_cbc_encrypt_unpadded(const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len,
                             const uint8_t iv[AES_BLOCK],
                             encrypt_block_fn encrypt,
                             const void *ctx)
{
    if (!in || !out || !out_len || !iv || !encrypt) return -1;
    if ((in_len % AES_BLOCK) != 0) return -2;

    uint8_t prev[AES_BLOCK];
    memcpy(prev, iv, AES_BLOCK);

    for (size_t off = 0; off < in_len; off += AES_BLOCK) {
        uint8_t block[AES_BLOCK];
        xor_block(block, in + off, prev);
        encrypt(block, out + off, ctx);
        memcpy(prev, out + off, AES_BLOCK);
    }

    *out_len = in_len;
    memset(prev, 0, AES_BLOCK);
    return 0;
}

int aes_cbc_decrypt_unpadded(const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t *out_len,
                             const uint8_t iv[AES_BLOCK],
                             decrypt_block_fn decrypt,
                             const void *ctx)
{
    if (!in || !out || !out_len || !iv || !decrypt) return -1;
    if ((in_len % AES_BLOCK) != 0) return -2;

    uint8_t prev[AES_BLOCK];
    memcpy(prev, iv, AES_BLOCK);

    for (size_t off = 0; off < in_len; off += AES_BLOCK) {
        uint8_t tmp[AES_BLOCK];
        decrypt(in + off, tmp, ctx);
        xor_block(out + off, tmp, prev);
        memcpy(prev, in + off, AES_BLOCK);
    }

    *out_len = in_len;
    memset(prev, 0, AES_BLOCK);
    return 0;
}

/* ===============================
 *  CBC with PKCS#7 padding
 * =============================== */
int aes_cbc_encrypt_padded(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len,
                           const uint8_t iv[AES_BLOCK],
                           encrypt_block_fn encrypt,
                           const void *ctx)
{
    uint8_t *padded = NULL;
    size_t padded_len = 0;

    // Allow NULL input only if length is zero
    const uint8_t *ptr = in_len > 0 ? in : (const uint8_t *)"\0";

    if (pkcs7_pad(ptr, in_len, AES_BLOCK, &padded, &padded_len) != PADDING_OK)
        return -1;

    int ret = aes_cbc_encrypt_unpadded(padded, padded_len, out, out_len, iv, encrypt, ctx);

    memset(padded, 0, padded_len);
    free(padded);
    return ret;
}


int aes_cbc_decrypt_padded(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len,
                           const uint8_t iv[AES_BLOCK],
                           decrypt_block_fn decrypt,
                           const void *ctx)
{
    if ((in_len % AES_BLOCK) != 0) return -1;

    size_t tmp_len = 0;
    int ret = aes_cbc_decrypt_unpadded(in, in_len, out, &tmp_len, iv, decrypt, ctx);
    if (ret != 0) return ret;

    uint8_t *unpadded = NULL;
    size_t plain_len = 0;
    if (pkcs7_unpad(out, tmp_len, AES_BLOCK, &unpadded, &plain_len) != PADDING_OK)
        return -2;

    if (out_len) *out_len = plain_len;
    memcpy(out, unpadded, plain_len);
    memset(unpadded, 0, plain_len);
    free(unpadded);
    return 0;
}
