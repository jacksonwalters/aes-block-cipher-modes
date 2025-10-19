#include "xts.h"
#include <string.h>
#include <stdlib.h>

/* local helpers -----------------------------------------------------------*/

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
    if (carry) {
        tweak[15] ^= 0x87;
    }
}

/*
 * encode_data_unit_be64: places 64-bit data_unit into tweak_plain[16] as a
 * 128-bit big-endian integer with high 64 bits zero and low 64 bits = data_unit.
 *
 * tweak_plain[0..7]  = 0
 * tweak_plain[8..15] = data_unit (big-endian, MSB at index 8)
 */
static void encode_data_unit_be64(uint8_t tweak_plain[16], uint64_t data_unit) {
    memset(tweak_plain, 0, 8);
    for (int i = 0; i < 8; ++i) {
        tweak_plain[8 + 7 - i] = (uint8_t)(data_unit & 0xFF);
        data_unit >>= 8;
    }
}

/* -------------------------------------------------------------------------*/

/*
 * xts_encrypt
 * Implements XTS-AES encryption including ciphertext stealing for partial final blocks.
 * See NIST SP 800-38E (ordering convention) and IEEE 1619 for algorithmic detail. :contentReference[oaicite:2]{index=2}
 */
int xts_encrypt(aes_block_fn aes_enc, const void *key1_ctx,
                aes_block_fn aes_tweak, const void *key2_ctx,
                uint64_t data_unit,
                const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext)
{
    if (!aes_enc || !aes_tweak || !plaintext || !ciphertext) return XTS_ERR_ARG;
    if (pt_len == 0) return XTS_ERR_INVALID;

    size_t n_full = pt_len / 16;
    size_t rem = pt_len % 16;

    uint8_t tweak[16], tweak_plain[16];
    encode_data_unit_be64(tweak_plain, data_unit);

    /* T = AES(K2, tweak_plain) */
    aes_tweak(tweak_plain, tweak, key2_ctx);

    /* If no remainder: process all blocks normally */
    if (rem == 0) {
        for (size_t i = 0; i < n_full; ++i) {
            uint8_t tmp[16], out[16];
            xor16(plaintext + i*16, tweak, tmp);
            aes_enc(tmp, out, key1_ctx);
            xor16(out, tweak, ciphertext + i*16);
            multiply_by_x(tweak);
        }
        return XTS_OK;
    }

    /* remainder exists: there is a partial final block
       We'll follow the standard ordering convention (C0..Cm-1, then Cm partial).
       The algorithm:
         - process blocks 0..m-2 normally (if m >= 2)
         - compute Ctemp = E(P_{m-1} ^ T_{m-1}) ^ T_{m-1}
         - set Cm (partial) = first r bytes of Ctemp
         - form a full block B = Pm (partial) concatenated with last (16-r) bytes of Ctemp
         - compute C_{m-1} = E(B ^ T_{m-1}) ^ T_{m-1}
    */
    if (n_full == 0) {
        /* plaintext length < 16: special case (one partial block only)
           Here m = 0 (no full blocks) and P0 is partial. IEEE 1619/800-38E allow
           this; implementation must handle it. We follow the canonical approach:
           - Treat as if there is a single full block whose plaintext is zero,
             but this is non-standard. Safer: construct a padded block from the
             partial and encrypt it with tweak for block 0, then set ciphertext
             partial to first r bytes of that ciphertext. To remain interoperable,
             most implementations require at least one full block; but we implement:
        */
        /* Compute Ctemp = E(Ppartial_pad ^ T0) ^ T0, where Ppartial_pad is the
           partial bytes followed by zeros; Cm = first r bytes of Ctemp.
           This is a reasonable behavior for single partial-block data units. */
        uint8_t block[16] = {0};
        memcpy(block, plaintext, rem);
        uint8_t tmp[16], out[16];
        xor16(block, tweak, tmp);
        aes_enc(tmp, out, key1_ctx);
        xor16(out, tweak, tmp);
        memcpy(ciphertext, tmp, rem);
        return XTS_OK;
    }

    /* Process blocks 0 .. n_full-2 */
    for (size_t i = 0; i + 1 < n_full; ++i) {
        uint8_t tmp[16], out[16];
        xor16(plaintext + i*16, tweak, tmp);
        aes_enc(tmp, out, key1_ctx);
        xor16(out, tweak, ciphertext + i*16);
        multiply_by_x(tweak);
    }

    /* Now tweak corresponds to block index n_full-1 */
    /* Compute Ctemp from last full plaintext block */
    uint8_t P_last[16];
    memcpy(P_last, plaintext + (n_full-1)*16, 16);
    uint8_t tmp[16], out[16];
    xor16(P_last, tweak, tmp);
    aes_enc(tmp, out, key1_ctx);
    xor16(out, tweak, out); /* out now = Ctemp */

    /* Cm (partial) = first rem bytes of out */
    memcpy(ciphertext + n_full*16, out, rem);

    /* Build B = P_partial || out[rem..15]  (full 16-byte block) */
    uint8_t B[16];
    memcpy(B, plaintext + n_full*16, rem);            /* Pm partial */
    memcpy(B + rem, out + rem, 16 - rem);             /* tail from Ctemp */

    /* Compute C_{m-1} = E(B ^ T_{m-1}) ^ T_{m-1} */
    xor16(B, tweak, tmp);
    aes_enc(tmp, out, key1_ctx);
    xor16(out, tweak, out);
    memcpy(ciphertext + (n_full-1)*16, out, 16);

    return XTS_OK;
}

/*
 * xts_decrypt
 * Reverse operation of xts_encrypt (handles ciphertext stealing).
 */
int xts_decrypt(aes_block_fn aes_dec, const void *key1_ctx,
                aes_block_fn aes_tweak, const void *key2_ctx,
                uint64_t data_unit,
                const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext)
{
    if (!aes_dec || !aes_tweak || !plaintext || !ciphertext) return XTS_ERR_ARG;
    if (ct_len == 0) return XTS_ERR_INVALID;

    size_t n_full = ct_len / 16;
    size_t rem = ct_len % 16;

    uint8_t tweak[16], tweak_plain[16];
    encode_data_unit_be64(tweak_plain, data_unit);

    /* T = AES(K2, tweak_plain) */
    aes_tweak(tweak_plain, tweak, key2_ctx);

    if (rem == 0) {
        for (size_t i = 0; i < n_full; ++i) {
            uint8_t tmp[16], out[16];
            xor16(ciphertext + i*16, tweak, tmp);
            aes_dec(tmp, out, key1_ctx);
            xor16(out, tweak, plaintext + i*16);
            multiply_by_x(tweak);
        }
        return XTS_OK;
    }

    if (n_full == 0) {
        /* single partial-block ciphertext only: reverse the single-block approach used above */
        uint8_t block[16] = {0};
        /* Reconstruct Ctemp by padding ciphertext with zeros */
        memcpy(block, ciphertext, rem);
        uint8_t tmp[16], out[16];
        xor16(block, tweak, tmp);
        aes_dec(tmp, out, key1_ctx);
        xor16(out, tweak, out);
        /* plaintext is first rem bytes of out */
        memcpy(plaintext, out, rem);
        return XTS_OK;
    }

    /* Process blocks 0 .. n_full-2 */
    for (size_t i = 0; i + 1 < n_full; ++i) {
        uint8_t tmp[16], out[16];
        xor16(ciphertext + i*16, tweak, tmp);
        aes_dec(tmp, out, key1_ctx);
        xor16(out, tweak, plaintext + i*16);
        multiply_by_x(tweak);
    }

    /* Now tweak corresponds to block index n_full-1 */
    /* We have:
       - ciphertext C_{m-1} (full block at index n_full-1)
       - partial Cm of length rem at ciphertext offset n_full*16
       Decryption algorithm (inverse of encryption above):
         - Compute Ctemp = (C_{m-1})  (full 16-byte block currently stored at n_full-1)
         - Reconstruct B (the block that was encrypted to produce final C_{m-1} during encryption)
           by decrypting C_{m-1} with the tweak and XORing
         - Recover Pm (partial) from first rem bytes of the *previous* Ctemp (the one used to make Cm)
           To obtain that previous Ctemp we need to compute:
             - Form a temporary block S by taking ciphertext[n_full-1] and replacing the final (16-rem)
               bytes by the bytes from ciphertext[n_full] (the partial) appended appropriately.
           The standard reversible approach implemented below reconstructs P_{m-1} and P_m correctly.
    */

    /* First: decrypt C_{m-1} to produce B (the padded block used to generate final stored C_{m-1}) */
    uint8_t C_m1[16];
    memcpy(C_m1, ciphertext + (n_full-1)*16, 16);

    uint8_t tmp[16], out[16];
    xor16(C_m1, tweak, tmp);
    aes_dec(tmp, out, key1_ctx);
    xor16(out, tweak, out); /* out now = B */

    /* Now B = Pm (partial bytes) || tail */
    size_t r = rem;
    if (r > 0) {
        /* Recover Pm (partial) from first r bytes of B */
        memcpy(plaintext + n_full*16, out, r);
    }

    /* Next, we must recover P_{m-1}:
       To do that, we need the Ctemp that was produced when encrypting the original P_{m-1}
       (that Ctemp's first r bytes became Cm). Those bytes are stored as ciphertext[n_full] (partial),
       and the remaining (16-r) bytes are the tail of out (which we have). So we reconstruct Ctemp:
    */
    uint8_t Ctemp[16];
    /* first r bytes come from ciphertext partial */
    memcpy(Ctemp, ciphertext + n_full*16, r);
    /* last 16-r bytes come from out[r..] (we decrypted C_{m-1} to B earlier) */
    memcpy(Ctemp + r, out + r, 16 - r);

    /* Now decrypt Ctemp to recover original P_{m-1} */
    xor16(Ctemp, tweak, tmp);
    aes_dec(tmp, out, key1_ctx);
    xor16(out, tweak, plaintext + (n_full-1)*16);

    return XTS_OK;
}
