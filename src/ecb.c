#include <stdlib.h>
#include <string.h>
#include "ecb.h"
#include "padding.h"

void aes_ecb_encrypt(const uint8_t *plaintext, uint8_t *ciphertext,
                     size_t length, const void *ctx)
{
    size_t blocks = length / 16;
    for (size_t i = 0; i < blocks; ++i) {
        aes_block_wrapper(plaintext + i*16, ciphertext + i*16, ctx);
    }
}

void aes_ecb_decrypt(const uint8_t *ciphertext, uint8_t *plaintext,
                     size_t length, const void *ctx)
{
    size_t blocks = length / 16;
    for (size_t i = 0; i < blocks; ++i) {
        aes_block_wrapper_dec(ciphertext + i*16, plaintext + i*16, ctx);
    }
}

int aes_ecb_encrypt_padded(const uint8_t *in, size_t in_len,
                           const void *ctx,
                           uint8_t **out, size_t *out_len)
{
    if (!out || !out_len || !ctx) return -1;      // mandatory pointers
    if (!in && in_len > 0) return -1;            // NULL only allowed if in_len>0
    if (!in) in = (const uint8_t *)"";          // empty input is valid

    uint8_t *padded = NULL;
    size_t padded_len = 0;
    if (pkcs7_pad(in, in_len, 16, &padded, &padded_len) != 0) return -2;

    uint8_t *cipher = (uint8_t *)malloc(padded_len);
    if (!cipher) { free(padded); return -3; }

    for (size_t i = 0; i < padded_len; i += 16)
        aes_block_wrapper(padded + i, cipher + i, ctx);

    free(padded);
    *out = cipher;
    *out_len = padded_len;
    return 0;
}

int aes_ecb_decrypt_padded(const uint8_t *in, size_t in_len,
                           const void *ctx,
                           uint8_t **out, size_t *out_len)
{
    if (!in || !ctx || !out || !out_len || (in_len % 16) != 0) return -1;

    uint8_t *decrypted = (uint8_t *)malloc(in_len);
    if (!decrypted) return -2;

    for (size_t i = 0; i < in_len; i += 16)
        aes_block_wrapper_dec(in + i, decrypted + i, ctx);

    uint8_t *unpadded = NULL;
    size_t plain_len = 0;
    if (pkcs7_unpad(decrypted, in_len, 16, &unpadded, &plain_len) != 0) {
        free(decrypted);
        return -3;
    }

    free(decrypted);
    *out = unpadded;
    *out_len = plain_len;
    return 0;
}

