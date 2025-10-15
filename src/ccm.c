#include "ccm.h"
#include "ctr.h"
#include "cmac.h"
#include "aes_wrapper.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Format B0 as per SP 800-38C */
static void format_b0(uint8_t B0[16], size_t pt_len, size_t ad_len,
                      size_t tag_len, const uint8_t *nonce, size_t n_len)
{
    memset(B0, 0, 16);
    uint8_t flags = 0;
    if (ad_len > 0) flags |= 0x40;             // Adata present
    flags |= ((tag_len - 2)/2) << 3;           // M field
    flags |= (15 - n_len);                     // L field
    B0[0] = flags;
    memcpy(B0+1, nonce, n_len);
    size_t q = 15 - n_len;
    for (size_t i = 0; i < q; i++)
        B0[15 - i] = (pt_len >> (8*i)) & 0xFF; // Big-endian length
}

/* Format AAD for CMAC */
static size_t write_aad(uint8_t *buf, const uint8_t *aad, size_t ad_len)
{
    size_t offset = 0;
    if (ad_len < 0xFF00) {
        buf[offset++] = (ad_len >> 8) & 0xFF;
        buf[offset++] = ad_len & 0xFF;
    } else {
        buf[offset++] = 0xFF;
        buf[offset++] = 0xFE;
        buf[offset++] = (ad_len >> 24) & 0xFF;
        buf[offset++] = (ad_len >> 16) & 0xFF;
        buf[offset++] = (ad_len >> 8) & 0xFF;
        buf[offset++] = ad_len & 0xFF;
    }
    if (aad && ad_len > 0) {
        memcpy(buf + offset, aad, ad_len);
        offset += ad_len;
    }
    size_t pad = (16 - (offset % 16)) % 16;
    if (pad) memset(buf + offset, 0, pad);
    return offset + pad;
}


/* AES-CCM encryption */
void aes_ccm_encrypt(const uint8_t *pt, size_t pt_len,
                     const uint8_t *aad, size_t ad_len,
                     const uint8_t *nonce, size_t n_len,
                     size_t tag_len,
                     uint8_t *ct, uint8_t *tag,
                     const struct aes_ctx *ctx)
{
    uint8_t B0[16];
    format_b0(B0, pt_len, ad_len, tag_len, nonce, n_len);
    printf("B0: "); for (size_t i=0;i<16;i++) printf("%02x ", B0[i]); printf("\n");

    /* CMAC input: B0 || AAD || PT */
    size_t aad_len_formatted = (aad && ad_len>0) ? ((ad_len<0xFF00)?2:6)+ad_len : 0;
    size_t pt_pad_len = (pt_len + 15) & ~0x0F; // pad to 16 bytes
    size_t cmac_len = 16 + aad_len_formatted + pt_pad_len;

    uint8_t *cmac_buf = calloc(1, cmac_len);
    memcpy(cmac_buf, B0, 16);
    if (aad_len_formatted > 0)
        write_aad(cmac_buf + 16, aad, ad_len);
    memcpy(cmac_buf + 16 + aad_len_formatted, pt, pt_len);
    printf("CMAC Input: "); for (size_t i=0;i<cmac_len;i++) printf("%02x ", cmac_buf[i]); printf("\n");

    uint8_t full_tag[16];
    aes_cmac(cmac_buf, cmac_len, full_tag, ctx);
    free(cmac_buf);
    printf("CMAC Full Tag: "); for (size_t i=0;i<tag_len;i++) printf("%02x ", full_tag[i]); printf("\n");

    /* Prepare counter blocks for CTR */
    uint8_t ctr[16] = {0};
    ctr[0] = 15 - n_len;
    memcpy(ctr+1, nonce, n_len);

    /* Encrypt plaintext */
    aes_ctr_crypt(pt, ct, pt_len, ctr, (block_encrypt_fn)aes_block_wrapper, ctx);
    
    /* Encrypt tag with S0 */
    memset(ctr + 1 + n_len, 0, 15 - n_len); // Counter = 0
    uint8_t S0[16];
    aes_block_wrapper(ctr, S0, ctx);
    for (size_t i = 0; i < tag_len; i++)
        tag[i] = full_tag[i] ^ S0[i];
    printf("S0: "); for (size_t i=0;i<16;i++) printf("%02x ", S0[i]); printf("\n");
    printf("Encrypted Tag: "); for (size_t i=0;i<tag_len;i++) printf("%02x ", tag[i]); printf("\n");
}

/* AES-CCM decryption */
int aes_ccm_decrypt(const uint8_t *ct, size_t ct_len,
                    const uint8_t *aad, size_t ad_len,
                    const uint8_t *nonce, size_t n_len,
                    size_t tag_len,
                    const uint8_t *tag,
                    uint8_t *pt,
                    const struct aes_ctx *ctx)
{
    uint8_t ctr[16] = {0};
    ctr[0] = 15 - n_len;
    memcpy(ctr+1, nonce, n_len);

    /* Decrypt ciphertext */
    aes_ctr_crypt(ct, pt, ct_len, ctr, (block_encrypt_fn)aes_block_wrapper, ctx);

    /* Recompute CMAC */
    uint8_t B0[16];
    format_b0(B0, ct_len, ad_len, tag_len, nonce, n_len);

    size_t aad_len_formatted = (aad && ad_len>0) ? ((ad_len<0xFF00)?2:6)+ad_len : 0;
    size_t pt_pad_len = (ct_len + 15) & ~0x0F;
    size_t cmac_len = 16 + aad_len_formatted + pt_pad_len;

    uint8_t *cmac_buf = calloc(1, cmac_len);
    memcpy(cmac_buf, B0, 16);
    if (aad_len_formatted > 0)
        write_aad(cmac_buf + 16, aad, ad_len);
    memcpy(cmac_buf + 16 + aad_len_formatted, pt, ct_len);

    uint8_t full_tag[16];
    aes_cmac(cmac_buf, cmac_len, full_tag, ctx);
    free(cmac_buf);

    /* Encrypt tag with S0 */
    memset(ctr + 1 + n_len, 0, 15 - n_len); // Counter = 0
    uint8_t S0[16];
    aes_block_wrapper(ctr, S0, ctx);
    for (size_t i = 0; i < tag_len; i++)
        full_tag[i] ^= S0[i];

    printf("Recomputed Tag: "); for (size_t i=0;i<tag_len;i++) printf("%02x ", full_tag[i]); printf("\n");
    printf("Input Tag: "); for (size_t i=0;i<tag_len;i++) printf("%02x ", tag[i]); printf("\n");

    return memcmp(full_tag, tag, tag_len) == 0 ? 0 : 1;
}
