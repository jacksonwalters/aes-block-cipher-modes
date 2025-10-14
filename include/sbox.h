#ifndef SBOX_H
#define SBOX_H

#include <stdint.h>

void initialize_aes_sbox(uint8_t sbox[256]);
void initialize_inverse_sbox(const uint8_t sbox[256], uint8_t inv_sbox[256]);

#endif
