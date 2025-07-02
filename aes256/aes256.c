#include <stdint.h>
#include <string.h> // for memcpy
#include "aes256.h"
#include "aes_defs.h"

// Forward declarations of helper functions
static void sub_bytes(uint8_t state[AES256_BLOCK_SIZE], const uint8_t sbox[256]);
static void shift_rows(uint8_t state[AES256_BLOCK_SIZE]);
static void mix_columns(uint8_t state[AES256_BLOCK_SIZE]);
static void add_round_key(uint8_t state[AES256_BLOCK_SIZE], const uint8_t round_key[AES256_BLOCK_SIZE]);

static void inv_sub_bytes(uint8_t state[AES256_BLOCK_SIZE], const uint8_t inv_sbox[256]);
static void inv_shift_rows(uint8_t state[AES256_BLOCK_SIZE]);
static void inv_mix_columns(uint8_t state[AES256_BLOCK_SIZE]);

// GF(2^8) multiplication helper used in mix_columns and inv_mix_columns
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) a ^= 0x1B; // irreducible polynomial
        b >>= 1;
    }
    return p;
}

void sub_bytes(uint8_t state[AES256_BLOCK_SIZE], const uint8_t sbox[256]) {
    for (int i = 0; i < AES256_BLOCK_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}

void shift_rows(uint8_t state[AES256_BLOCK_SIZE]) {
    // Row 1: rotate left by 1
    uint8_t tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    // Row 2: rotate left by 2
    tmp = state[2];
    uint8_t tmp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = tmp;
    state[14] = tmp2;

    // Row 3: rotate left by 3
    tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = tmp;
}

void mix_columns(uint8_t state[AES256_BLOCK_SIZE]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = &state[c * 4];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];

        col[0] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        col[1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        col[2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        col[3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

void add_round_key(uint8_t state[AES256_BLOCK_SIZE], const uint8_t round_key[AES256_BLOCK_SIZE]) {
    for (int i = 0; i < AES256_BLOCK_SIZE; i++) {
        state[i] ^= round_key[i];
    }
}

void aes256_encrypt_block(const uint8_t input[AES256_BLOCK_SIZE], uint8_t output[AES256_BLOCK_SIZE],
                          const uint8_t round_keys[AES256_EXPANDED_KEY_SIZE], const uint8_t sbox[256]) {
    uint8_t state[AES256_BLOCK_SIZE];
    memcpy(state, input, AES256_BLOCK_SIZE);

    add_round_key(state, round_keys);

    for (int round = 1; round < AES256_NUM_ROUNDS; round++) {
        sub_bytes(state, sbox);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * AES256_BLOCK_SIZE);
    }

    // Final round (no mix_columns)
    sub_bytes(state, sbox);
    shift_rows(state);
    add_round_key(state, round_keys + AES256_NUM_ROUNDS * AES256_BLOCK_SIZE);

    memcpy(output, state, AES256_BLOCK_SIZE);
}

// ---------- Inverse functions ------------

void initialize_inverse_sbox(const uint8_t sbox[256], uint8_t inv_sbox[256]) {
    for (int i = 0; i < 256; i++) {
        inv_sbox[sbox[i]] = (uint8_t)i;
    }
}

void inv_sub_bytes(uint8_t state[AES256_BLOCK_SIZE], const uint8_t inv_sbox[256]) {
    for (int i = 0; i < AES256_BLOCK_SIZE; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

void inv_shift_rows(uint8_t state[AES256_BLOCK_SIZE]) {
    // Row 1: rotate right by 1
    uint8_t tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    // Row 2: rotate right by 2
    tmp = state[2];
    uint8_t tmp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = tmp;
    state[14] = tmp2;

    // Row 3: rotate right by 3
    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

void inv_mix_columns(uint8_t state[AES256_BLOCK_SIZE]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = &state[c * 4];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];

        col[0] = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        col[1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        col[2] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        col[3] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

void aes256_decrypt_block(const uint8_t input[AES256_BLOCK_SIZE], uint8_t output[AES256_BLOCK_SIZE],
                          const uint8_t round_keys[AES256_EXPANDED_KEY_SIZE], const uint8_t sbox[256]) {
    uint8_t state[AES256_BLOCK_SIZE];
    uint8_t inv_sbox[256];
    initialize_inverse_sbox(sbox, inv_sbox);

    memcpy(state, input, AES256_BLOCK_SIZE);

    add_round_key(state, round_keys + AES256_NUM_ROUNDS * AES256_BLOCK_SIZE);

    for (int round = AES256_NUM_ROUNDS - 1; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state, inv_sbox);
        add_round_key(state, round_keys + round * AES256_BLOCK_SIZE);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state, inv_sbox);
    add_round_key(state, round_keys);

    memcpy(output, state, AES256_BLOCK_SIZE);
}
