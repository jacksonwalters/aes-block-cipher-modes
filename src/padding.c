#include "padding.h"
#include <stdlib.h>
#include <string.h>

/* Constant-time check: all bytes in buf[0..n-1] == val */
static int ct_mem_is_value(const uint8_t *buf, size_t n, uint8_t val) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= buf[i] ^ val;
    }
    return diff == 0;
}

int pkcs7_pad(const uint8_t *in, size_t in_len, size_t block_size,
              uint8_t **out, size_t *out_len)
{
    if (!in || !out || !out_len || block_size == 0 || block_size > 255)
        return PADDING_ERR_INVALID;

    size_t pad_len = block_size - (in_len % block_size);
    if (pad_len == 0) pad_len = block_size; /* full block padding */

    size_t total = in_len + pad_len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return PADDING_ERR_NOMEM;

    if (in_len > 0) memcpy(buf, in, in_len);
    memset(buf + in_len, (uint8_t)pad_len, pad_len);

    *out = buf;
    *out_len = total;
    return PADDING_OK;
}

int pkcs7_unpad(const uint8_t *in, size_t in_len, size_t block_size,
                uint8_t **out, size_t *out_len)
{
    if (!in || !out || !out_len || block_size == 0 || block_size > 255)
        return PADDING_ERR_INVALID;
    if (in_len == 0 || (in_len % block_size) != 0)
        return PADDING_ERR_INVALID;

    uint8_t pad_val = in[in_len - 1];
    if (pad_val == 0 || pad_val > block_size)
        return PADDING_ERR_INVALID;

    if (!ct_mem_is_value(in + (in_len - pad_val), pad_val, pad_val))
        return PADDING_ERR_INVALID;

    size_t plain_len = in_len - pad_val;
    uint8_t *buf = (uint8_t *)malloc(plain_len ? plain_len : 1);
    if (!buf) return PADDING_ERR_NOMEM;

    if (plain_len > 0) memcpy(buf, in, plain_len);

    *out = buf;
    *out_len = plain_len;
    return PADDING_OK;
}
