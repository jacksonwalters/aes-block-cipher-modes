#ifndef PADDING_H
#define PADDING_H

#include <stddef.h>
#include <stdint.h>

#define PADDING_OK 0
#define PADDING_ERR_INVALID -1
#define PADDING_ERR_NOMEM -2

/* Pad `in` (length in_len) to multiple of block_size.
 * Allocates new buffer in *out (caller frees it).
 */
int pkcs7_pad(const uint8_t *in, size_t in_len, size_t block_size,
              uint8_t **out, size_t *out_len);

/* Remove PKCS#7 padding from `in` (length in_len),
 * allocates unpadded buffer in *out (caller frees it).
 */
int pkcs7_unpad(const uint8_t *in, size_t in_len, size_t block_size,
                uint8_t **out, size_t *out_len);

#endif /* PADDING_H */
