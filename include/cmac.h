#ifndef CMAC_H
#define CMAC_H

#include <stddef.h>
#include <stdint.h>
#include "aes_wrapper.h"  // for struct aes_ctx

/* Compute AES-CMAC on input message
 * message: pointer to input data
 * length: length of input in bytes
 * tag: 16-byte output CMAC
 * ctx: pointer to AES context (round keys, sbox)
 */
void aes_cmac(const uint8_t *message, size_t length,
              uint8_t tag[16], const void *ctx);

#endif