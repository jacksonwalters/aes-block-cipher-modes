#ifndef AES_H
#define AES_H

#include <stdint.h>

void aes_encrypt_block(const uint8_t input[16], uint8_t output[16], const uint8_t round_keys[176], const uint8_t sbox[256]);
void aes_decrypt_block(const uint8_t input[16], uint8_t output[16], const uint8_t round_keys[176], const uint8_t sbox[256]);
void initialize_inverse_sbox(const uint8_t sbox[256], uint8_t inv_sbox[256]);

#endif // AES_H

