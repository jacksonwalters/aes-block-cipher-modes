#include "../include/aes_128.h"
#include "../include/sbox.h"

// Internal helpers
static void add_round_key(uint8_t state[16], const uint8_t *round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static void sub_bytes(uint8_t state[16], const uint8_t sbox[256]) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void shift_rows(uint8_t state[16]) {
    uint8_t tmp;

    // Row 1: shift left by 1
    tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    // Row 2: shift left by 2
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    // Row 3: shift left by 3 (or right by 1)
    tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = tmp;
}

// GF(2^8) multiplication by 2
static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0);
}

static void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = &state[c * 4];
        uint8_t t = col[0] ^ col[1] ^ col[2] ^ col[3];
        uint8_t tmp0 = col[0];
        uint8_t tmp1 = col[1];
        uint8_t tmp2 = col[2];
        uint8_t tmp3 = col[3];

        col[0] ^= t ^ xtime(tmp0 ^ tmp1);
        col[1] ^= t ^ xtime(tmp1 ^ tmp2);
        col[2] ^= t ^ xtime(tmp2 ^ tmp3);
        col[3] ^= t ^ xtime(tmp3 ^ tmp0);
    }
}

void aes_encrypt_block(const uint8_t input[16], uint8_t output[16], const uint8_t round_keys[176], const uint8_t sbox[256]) {
    uint8_t state[16];

    // Copy input into state
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }

    // Initial round key
    add_round_key(state, round_keys);

    // 9 main rounds
    for (int round = 1; round <= 9; round++) {
        sub_bytes(state, sbox);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * 16);
    }

    // Final round
    sub_bytes(state, sbox);
    shift_rows(state);
    add_round_key(state, round_keys + 10 * 16);

    // Copy state to output
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
}

// Inverse ShiftRows
static void inv_shift_rows(uint8_t state[16]) {
    uint8_t tmp;

    // Row 1: shift right by 1
    tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    // Row 2: shift right by 2
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    // Row 3: shift right by 3 (or left by 1)
    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

// GF(2^8) multiplication helper for inverse MixColumns
static uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            p ^= a;
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1b; // AES irreducible polynomial
        b >>= 1;
    }
    return p;
}

static void inv_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = &state[c * 4];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];

        col[0] = mul(a0, 0x0e) ^ mul(a1, 0x0b) ^ mul(a2, 0x0d) ^ mul(a3, 0x09);
        col[1] = mul(a0, 0x09) ^ mul(a1, 0x0e) ^ mul(a2, 0x0b) ^ mul(a3, 0x0d);
        col[2] = mul(a0, 0x0d) ^ mul(a1, 0x09) ^ mul(a2, 0x0e) ^ mul(a3, 0x0b);
        col[3] = mul(a0, 0x0b) ^ mul(a1, 0x0d) ^ mul(a2, 0x09) ^ mul(a3, 0x0e);
    }
}

static void inv_sub_bytes(uint8_t state[16], const uint8_t inv_sbox[256]) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

void aes_decrypt_block(const uint8_t input[16], uint8_t output[16], const uint8_t round_keys[176], const uint8_t sbox[256]) {
    uint8_t state[16];
    uint8_t inv_sbox[256];

    // Generate inverse S-box
    initialize_inverse_sbox(sbox, inv_sbox);

    // Copy input to state
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }

    // Initial AddRoundKey with last round key
    add_round_key(state, round_keys + 10 * 16);

    // 9 rounds
    for (int round = 9; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state, inv_sbox);
        add_round_key(state, round_keys + round * 16);
        inv_mix_columns(state);
    }

    // Final round
    inv_shift_rows(state);
    inv_sub_bytes(state, inv_sbox);
    add_round_key(state, round_keys);

    // Copy state to output
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
}

