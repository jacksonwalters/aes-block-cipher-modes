#include "key_expansion_256.h"
#include "aes_defs.h"  // AES256_KEY_SIZE, AES256_EXPANDED_KEY_SIZE
#include <stdint.h>

// AES-256 uses 8-word key, 14 rounds → 60 words total
// Rcon values
static const uint8_t rcon[15] = {
    0x00, // rcon[0] unused
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36, 0x6C, 0xD8, 0xAB
};

// Rotate a 4-byte word left
static void rot_word(uint8_t w[4]) {
    uint8_t tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

// Apply S-box to 4-byte word
static void sub_word(uint8_t w[4], const uint8_t sbox[256]) {
    for (int i = 0; i < 4; i++) {
        w[i] = sbox[w[i]];
    }
}

void aes_key_expansion_256(const uint8_t key[AES256_KEY_SIZE],
                           uint8_t round_keys[AES256_EXPANDED_KEY_SIZE],
                           const uint8_t sbox[256])
{
    int Nk = 8;   // number of 32-bit words in key
    int Nr = 14;  // number of rounds
    int Nb = 4;   // number of words per block (AES standard)

    // Copy original key (32 bytes) into first 8 words
    for (int i = 0; i < Nk * 4; i++) {
        round_keys[i] = key[i];
    }

    uint8_t temp[4];
    int bytes_generated = Nk * 4; // 32
    int rcon_idx = 1;

    while (bytes_generated < Nb * (Nr + 1) * 4) { // 4*(Nr+1)*Nb = 240
        // Copy previous word into temp
        for (int i = 0; i < 4; i++) {
            temp[i] = round_keys[bytes_generated - 4 + i];
        }

        int word_index = bytes_generated / 4;

        if (word_index % Nk == 0) {
            rot_word(temp);
            sub_word(temp, sbox);
            temp[0] ^= rcon[rcon_idx++];
        } else if (Nk > 6 && word_index % Nk == 4) {
            sub_word(temp, sbox);
        }

        // XOR with word Nk positions earlier
        for (int i = 0; i < 4; i++) {
            round_keys[bytes_generated] = round_keys[bytes_generated - Nk * 4] ^ temp[i];
            bytes_generated++;
        }
    }
}
