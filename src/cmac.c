#include "cmac.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* XOR two 16-byte blocks */
static void xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
}

/* Left shift a 16-byte block by 1 bit */
static void shift_left(uint8_t out[16], const uint8_t in[16]) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t new_carry = (in[i] & 0x80) ? 1 : 0;
        out[i] = (in[i] << 1) | carry;
        carry = new_carry;
    }
}

/* Generate subkeys K1 and K2 according to NIST SP 800-38B */
static void generate_subkeys(uint8_t K1[16], uint8_t K2[16], const void *ctx) {
    uint8_t L[16] = {0};
    uint8_t zero[16] = {0};
    // Encrypt the zero block to get L
    aes_block_wrapper(zero, L, ctx);

    const uint8_t Rb[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x87};

    // K1 = L << 1. If MSB(L)=1, K1 XOR Rb
    shift_left(K1, L);
    if (L[0] & 0x80) {
        xor_block(K1, K1, Rb);
    }

    // K2 = K1 << 1. If MSB(K1)=1, K2 XOR Rb
    shift_left(K2, K1);
    if (K1[0] & 0x80) {
        xor_block(K2, K2, Rb);
    }
}

/* Pad a block (0x80 followed by zeros) for partial/empty blocks */
static void pad_block(uint8_t out[16], const uint8_t *in, size_t len) {
    memset(out, 0, 16);
    if (len > 0 && in != NULL) memcpy(out, in, len);
    if (len < 16) out[len] = 0x80;
}

void aes_cmac(const uint8_t *message, size_t length, uint8_t tag[16], const void *ctx) {
    uint8_t K1[16], K2[16];
    generate_subkeys(K1, K2, ctx);

    // If length == 0, n_blocks = 1. If length = 36, n_blocks = 3.
    size_t n_blocks = (length == 0) ? 1 : (length + 15) / 16;
    uint8_t C[16] = {0}; // Current chaining block, C0 is all zeros

    // Calculate the length of the message that is NOT the final block.
    // This is 0 if n_blocks=1.
    size_t processed_len = (n_blocks - 1) * 16;
    
    // Case 1: Complete final block (L > 0 and L is a multiple of 16) -> use K1
    int last_is_complete = (length > 0) && (length % 16 == 0);

    // Process all full blocks except the last one
    for (size_t i = 0; i < processed_len; i += 16) {
        uint8_t Y[16];
        xor_block(Y, C, message + i);
        aes_block_wrapper(Y, C, ctx);
    }
    
    // Prepare the last block M_last (M_n XOR K1 or M_n* XOR K2)
    uint8_t M_last[16];
    
    if (last_is_complete) {
        // Full block (e.g., L=32): M_last = M_n XOR K1. 
        // The last block starts at message + length - 16.
        memcpy(M_last, message + length - 16, 16);
        xor_block(M_last, M_last, K1);
    } else {
        // Partial block (e.g., L=36) or L=0: M_last = M_n* XOR K2.
        size_t last_len = length % 16; // 4 for L=36, 0 for L=0
        
        if (length == 0) {
            // Empty message
            pad_block(M_last, NULL, 0); 
        } else {
            // Partial message: M_last starts at message + processed_len.
            pad_block(M_last, message + processed_len, last_len);
        }
        xor_block(M_last, M_last, K2);
    }

    // Process last block: T = E(C XOR M_last)
    uint8_t Y_last[16];
    xor_block(Y_last, C, M_last);
    aes_block_wrapper(Y_last, tag, ctx);
}
