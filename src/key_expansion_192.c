#include <stdint.h>
#include "key_expansion_192.h"
#include "sbox.h"

// AES-192 Key Expansion
// Input: 24 bytes (192 bits)
// Output: 208 bytes (13 round keys * 16 bytes)
void aes_key_expansion_192(const uint8_t key[24], uint8_t round_keys[208], const uint8_t sbox[256]) {
    const uint8_t rcon[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    
    // Copy original key
    for (int i = 0; i < 24; i++) {
        round_keys[i] = key[i];
    }

    // Generate remaining key material
    // AES-192 needs 52 words (208 bytes) total
    // We have 6 words already, need 46 more
    int bytes_generated = 24;
    int rcon_iteration = 0;

    while (bytes_generated < 208) {
        uint8_t temp[4];
        
        // Copy last 4 bytes of previous block
        for (int i = 0; i < 4; i++) {
            temp[i] = round_keys[bytes_generated - 4 + i];
        }

        // Every 6 words (24 bytes), apply core schedule
        if (bytes_generated % 24 == 0) {
            // RotWord
            uint8_t tmp = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = tmp;

            // SubWord
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }

            // XOR with Rcon
            temp[0] ^= rcon[rcon_iteration++];
        }

        // XOR with word from 6 positions back (24 bytes)
        for (int i = 0; i < 4; i++) {
            round_keys[bytes_generated] = round_keys[bytes_generated - 24] ^ temp[i];
            bytes_generated++;
        }
    }
}