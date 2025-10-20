#include "kw.h"
#include <string.h>
#include <stdint.h>

static const uint8_t ICV1[8] = { 0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6 };

static void xor64(uint8_t *block, uint64_t t) {
    for (int i = 0; i < 8; i++) {
        block[i] ^= (uint8_t)(t >> (56 - 8 * i));
    }
}

int kw_wrap(const uint8_t *plaintext, size_t plen,
            uint8_t *ciphertext, const struct aes_ctx *ctx)
{
    if (!plaintext || !ciphertext || !ctx) return -1;
    if (plen % 8 != 0 || plen < 16) return -1;

    size_t n = plen / 8;
    if (n > 32) return -1;

    uint8_t A[8];
    memcpy(A, ICV1, 8);
    uint8_t R[32][8];

    for (size_t i = 0; i < n; i++) {
        memcpy(R[i], plaintext + 8*i, 8);
    }

    uint8_t B[16];
    for (size_t j = 0; j <= 5; j++) {
        for (size_t i = 0; i < n; i++) {
            memcpy(B, A, 8);
            memcpy(B+8, R[i], 8);
            aes_block_wrapper(B, B, ctx);
            uint64_t t = (uint64_t)(n * j + i + 1);
            memcpy(A, B, 8);
            xor64(A, t);
            memcpy(R[i], B+8, 8);
        }
    }

    memcpy(ciphertext, A, 8);
    for (size_t i = 0; i < n; i++) {
        memcpy(ciphertext + 8*(i+1), R[i], 8);
    }

    return 0;
}

int kw_unwrap(const uint8_t *ciphertext, size_t clen,
              uint8_t *plaintext, const struct aes_ctx *ctx)
{
    if (!ciphertext || !plaintext || !ctx) return -1;
    if (clen % 8 != 0 || clen < 24) return -1;

    size_t n = clen/8 - 1;
    if (n > 32) return -1;

    uint8_t A[8];
    memcpy(A, ciphertext, 8);
    uint8_t R[32][8];
    for (size_t i = 0; i < n; i++) {
        memcpy(R[i], ciphertext + 8*(i+1), 8);
    }

    uint8_t B[16];
    for (int j = 5; j >= 0; j--) {
        for (int i = (int)n-1; i >= 0; i--) {
            uint64_t t = (uint64_t)(n * j + i + 1);
            xor64(A, t);
            memcpy(B, A, 8);
            memcpy(B+8, R[i], 8);
            aes_block_wrapper_dec(B, B, ctx);
            memcpy(A, B, 8);
            memcpy(R[i], B+8, 8);
        }
    }

    if (memcmp(A, ICV1, 8) != 0) {
        return -1;
    }

    for (size_t i = 0; i < n; i++) {
        memcpy(plaintext + 8*i, R[i], 8);
    }

    return 0;
}
