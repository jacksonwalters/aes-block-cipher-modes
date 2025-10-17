#include "gcm.h"
#include "ctr.h"
#include "sbox.h"
#include "key_expansion_128.h"
#include "key_expansion_192.h"
#include "key_expansion_256.h"
#include "aes_wrapper.h"
#include <string.h>
#include <stdio.h>

/* XOR two 16-byte blocks */
static void xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
}

/* GHASH multiplication in GF(2^128) */
static void ghash_mult(uint8_t out[16], const uint8_t X[16], const uint8_t H[16]) {
    uint8_t Z[16] = {0};
    uint8_t V[16]; memcpy(V,H,16);

    for(int i=0;i<16;i++){
        for(int j=7;j>=0;j--){
            if((X[i]>>j)&1) for(int k=0;k<16;k++) Z[k]^=V[k];
            int carry=0;
            for(int k=0;k<16;k++){
                int tmp=V[k];
                V[k]=(tmp>>1)|carry;
                carry=(tmp&1)?0x80:0;
            }
            if(carry) V[0]^=0xe1;
        }
    }
    memcpy(out,Z,16);
}

/* GHASH over arbitrary data */
void ghash(uint8_t out[16], const uint8_t *aad, size_t aad_len,
                  const uint8_t *c, size_t c_len, const uint8_t H[16]) {
    uint8_t Y[16] = {0};
    size_t i;

    /* Process AAD */
    for (i=0;i+16<=aad_len;i+=16){
        xor_block(Y,Y,aad+i);
        ghash_mult(Y,Y,H);
    }
    if (i<aad_len){
        uint8_t tmp[16]={0};
        memcpy(tmp,aad+i,aad_len-i);
        xor_block(Y,Y,tmp);
        ghash_mult(Y,Y,H);
    }

    /* Process ciphertext */
    for (i=0;i+16<=c_len;i+=16){
        xor_block(Y,Y,c+i);
        ghash_mult(Y,Y,H);
    }
    if (i<c_len){
        uint8_t tmp[16]={0};
        memcpy(tmp,c+i,c_len-i);
        xor_block(Y,Y,tmp);
        ghash_mult(Y,Y,H);
    }

    /* Length block */
    uint8_t len_block[16]={0};
    uint64_t aad_bits=aad_len*8;
    uint64_t c_bits=c_len*8;
    for(int j=0;j<8;j++){
        len_block[7-j]=(aad_bits>>(8*j))&0xFF;
        len_block[15-j]=(c_bits>>(8*j))&0xFF;
    }
    xor_block(Y,Y,len_block);
    ghash_mult(Y,Y,H);

    memcpy(out,Y,16);
}

/* Initialize GCM context - returns 0 on success, -1 on error */
int gcm_init(struct gcm_ctx *ctx, const uint8_t *key, size_t key_len,
              const uint8_t *iv, size_t iv_len){

    initialize_aes_sbox(ctx->sbox);

    if(key_len == 16) {
        aes_key_expansion(key, ctx->round_keys, ctx->sbox);
    } else if(key_len == 24) {
        aes_key_expansion_192(key, ctx->round_keys, ctx->sbox);
    } else if(key_len == 32) {
        aes_key_expansion_256(key, ctx->round_keys, ctx->sbox);
    } else {
        return -1;  // Unsupported key length
    }

    ctx->aes.round_keys = ctx->round_keys;
    ctx->aes.sbox = ctx->sbox;
    ctx->aes.key_len = key_len;

    /* H = AES(K,0^128) */
    uint8_t zero[16] = {0};
    aes_block_wrapper(zero, ctx->H, &ctx->aes);

    /* IV -> J0 */
    if(iv_len == 12){
        memcpy(ctx->J0, iv, 12);
        memset(ctx->J0 + 12, 0, 4);  // Zero out all 4 bytes
        ctx->J0[15] = 0x01;           // Then set the last byte to 1
    } else {
        /* GHASH IV */
        ghash(ctx->J0, NULL, 0, iv, iv_len, ctx->H);
    }
    
    return 0;  // Success
}

/* Encrypt with AES-GCM */
void gcm_encrypt(struct gcm_ctx *ctx, const uint8_t *plaintext, size_t len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *ciphertext, uint8_t *tag, size_t tag_len){

    if(tag_len>16) tag_len=16;

    uint8_t counter[16]; memcpy(counter,ctx->J0,16);
    ctr_increment(counter);

    aes_ctr_crypt(plaintext,ciphertext,len,counter,aes_block_wrapper,&ctx->aes);

    uint8_t ghash_out[16];
    ghash(ghash_out,aad,aad_len,ciphertext,len,ctx->H);

    uint8_t S[16]; 
    aes_block_wrapper(ctx->J0,S,&ctx->aes);

    for(size_t i=0;i<tag_len;i++) tag[i]=ghash_out[i]^S[i];
}

/* Decrypt with AES-GCM */
int gcm_decrypt(struct gcm_ctx *ctx, const uint8_t *ciphertext, size_t len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *tag, size_t tag_len,
                uint8_t *plaintext){

    if(tag_len>16) tag_len=16;

    uint8_t ghash_out[16];
    ghash(ghash_out,aad,aad_len,ciphertext,len,ctx->H);

    uint8_t S[16]; 
    aes_block_wrapper(ctx->J0,S,&ctx->aes);

    uint8_t computed_tag[16];
    for(size_t i=0;i<tag_len;i++) computed_tag[i]=ghash_out[i]^S[i];

    if(memcmp(tag,computed_tag,tag_len)!=0) {
        memset(plaintext, 0, len);
        return -1;
    }

    uint8_t counter[16]; memcpy(counter,ctx->J0,16);
    ctr_increment(counter);

    aes_ctr_crypt(ciphertext,plaintext,len,counter,aes_block_wrapper,&ctx->aes);

    return 0;
}
