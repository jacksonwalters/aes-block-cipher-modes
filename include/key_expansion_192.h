#ifndef KEY_EXPANSION_192_H
#define KEY_EXPANSION_192_H

#include <stdint.h>

// AES-192 key expansion
// Input: 24-byte key
// Output: 208 bytes (13 round keys of 16 bytes each)
void aes_key_expansion_192(const uint8_t key[24], uint8_t round_keys[208], const uint8_t sbox[256]);

#endif // KEY_EXPANSION_192_H