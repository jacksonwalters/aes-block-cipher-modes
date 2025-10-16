#ifndef AES_192_H
#define AES_192_H

#include <stdint.h>

// AES-192 block encryption (12 rounds)
void aes_encrypt_block_192(const uint8_t input[16], uint8_t output[16], 
                           const uint8_t round_keys[208], const uint8_t sbox[256]);

// AES-192 block decryption (12 rounds)
void aes_decrypt_block_192(const uint8_t input[16], uint8_t output[16], 
                           const uint8_t round_keys[208], const uint8_t sbox[256]);

#endif // AES_192_H