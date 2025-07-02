#ifndef KEY_EXPANSION_H
#define KEY_EXPANSION_H

#include <stdint.h>
#include "aes_defs.h" // AES-256 constants

// Expand the 256-bit key into the round keys using the provided sbox
void aes256_key_expansion(const uint8_t key[AES256_KEY_SIZE], uint8_t expanded_keys[AES256_EXPANDED_KEY_SIZE], const uint8_t sbox[256]);

#endif // KEY_EXPANSION_H


