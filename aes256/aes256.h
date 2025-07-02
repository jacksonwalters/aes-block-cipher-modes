#ifndef AES_H
#define AES_H

#include <stdint.h>
#include "aes_defs.h" // AES-256 constants

// Encrypt one 16-byte block using AES-256
void aes256_encrypt_block(const uint8_t input[AES256_BLOCK_SIZE], uint8_t output[AES256_BLOCK_SIZE],
                          const uint8_t round_keys[AES256_EXPANDED_KEY_SIZE], const uint8_t sbox[256]);

// Decrypt one 16-byte block using AES-256
void aes256_decrypt_block(const uint8_t input[AES256_BLOCK_SIZE], uint8_t output[AES256_BLOCK_SIZE],
                          const uint8_t round_keys[AES256_EXPANDED_KEY_SIZE], const uint8_t sbox[256]);

// Generate inverse S-box from S-box
void initialize_inverse_sbox(const uint8_t sbox[256], uint8_t inv_sbox[256]);

#endif // AES_H


