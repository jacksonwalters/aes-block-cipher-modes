#include "cbc.h"
#include "padding.h"
#include <string.h>
#include <stdlib.h>

/* XOR helper */
static inline void xor_block(uint8_t out[AES_BLOCK],
                             const uint8_t a[AES_BLOCK],
                             const uint8_t b[AES_BLOCK])
{
    for (int i = 0; i < AES_BLOCK; ++i)
        out[i] = a[i] ^ b[i];
}

int aes_cbc_encrypt(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len,
                    const uint8_t iv[AES_BLOCK],
                    encrypt_block_fn encrypt, const void *ctx)
{
    if (!out || !out_len || !iv || !encrypt) return -1;
    if (!in && in_len > 0) return -1; // NULL only allowed if in_len==0
    if (!in) in = (const uint8_t *)""; // empty input is valid

    uint8_t *padded = NULL;
    size_t padded_len = 0;
    if (pkcs7_pad(in, in_len, AES_BLOCK, &padded, &padded_len) != PADDING_OK)
        return -2;

    uint8_t prev[AES_BLOCK];
    memcpy(prev, iv, AES_BLOCK);

    for (size_t off = 0; off < padded_len; off += AES_BLOCK) {
        uint8_t block[AES_BLOCK];
        xor_block(block, padded + off, prev);
        encrypt(block, out + off, ctx);
        memcpy(prev, out + off, AES_BLOCK);
    }

    *out_len = padded_len;
    memset(prev, 0, AES_BLOCK);
    memset(padded, 0, padded_len);
    free(padded);
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
        decrypt(in + off, tmp, ctx);
        xor_block(out + off, tmp, prev);
        memcpy(prev, in + off, AES_BLOCK);
    }

    /* Unpad using reusable PKCS#7 function */
    uint8_t *unpadded = NULL;
    size_t plain_len = 0;
    if (pkcs7_unpad(out, in_len, AES_BLOCK, &unpadded, &plain_len) != PADDING_OK) {
        memset(out, 0, in_len);
        memset(prev, 0, AES_BLOCK);
        return -3;
    }

    memcpy(out, unpadded, plain_len);
    *out_len = plain_len;
    memset(unpadded, 0, plain_len);
    free(unpadded);
    memset(prev, 0, AES_BLOCK);
    return 0;
}
