#include "key_expansion_256.h"
#include "aes_defs.h" // AES-256 constants

static uint8_t rcon[11] = {
    0x00, // rcon[0] unused
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
};

void aes256_key_expansion(const uint8_t key[AES256_KEY_SIZE], uint8_t round_keys[AES256_EXPANDED_KEY_SIZE], const uint8_t sbox[256]) {
    // First 16 bytes are the original key
    for (int i = 0; i < 16; i++) {
        round_keys[i] = key[i];
    }

    uint8_t temp[4];
    int bytes_generated = 16;
    int rcon_idx = 1;

    while (bytes_generated < 176) {
        // Last 4 bytes of previous key part
        for (int i = 0; i < 4; i++) {
            temp[i] = round_keys[bytes_generated - 4 + i];
        }

        if (bytes_generated % 16 == 0) {
            // Rotate
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // Apply S-box
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }

            // XOR with rcon
            temp[0] ^= rcon[rcon_idx++];
        }

        // XOR with 16 bytes earlier
        for (int i = 0; i < 4; i++) {
            round_keys[bytes_generated] = round_keys[bytes_generated - 16] ^ temp[i];
            bytes_generated++;
        }
    }
}
