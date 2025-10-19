#ifndef KEY_EXPANSION_128_H
#define KEY_EXPANSION_128_H

#include <stdint.h>

void aes_key_expansion_128(const uint8_t key[16], uint8_t round_keys[176], const uint8_t sbox[256]);

#endif // KEY_EXPANSION_128_H
