#include "aes.h"

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
