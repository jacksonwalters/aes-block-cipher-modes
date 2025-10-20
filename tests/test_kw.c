#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../include/kw.h"
#include "../include/aes_wrapper.h"
#include "../include/key_expansion_128.h"
#include "../include/sbox.h"

static void hexprint(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
}

int main(void) {
    const uint8_t kek[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };

    const uint8_t plaintext[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };

    const uint8_t expected[24] = {
        0x1F,0xA6,0x8B,0x0A,0x81,0x12,0xB4,0x47,
        0xAE,0xF3,0x4B,0xD8,0xFB,0x5A,0x7B,0x82,
        0x9D,0x3E,0x86,0x23,0x71,0xD2,0xCF,0xE5
    };

    uint8_t round_keys[176];
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(kek, round_keys, sbox);

    struct aes_ctx ctx = {
        .round_keys = round_keys,
        .sbox = sbox,
        .key_len = 16
    };

    uint8_t wrapped[24];
    uint8_t unwrapped[16];

    int rc = kw_wrap(plaintext, sizeof(plaintext), wrapped, &ctx);
    if (rc != 0 || memcmp(wrapped, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "KW wrap failed!\nExpected: ");
        hexprint(expected, sizeof(expected));
        fprintf(stderr, "\nGot:      ");
        hexprint(wrapped, sizeof(wrapped));
        fprintf(stderr, "\n");
        return 1;
    }

    rc = kw_unwrap(wrapped, sizeof(wrapped), unwrapped, &ctx);
    if (rc != 0 || memcmp(unwrapped, plaintext, sizeof(plaintext)) != 0) {
        fprintf(stderr, "KW unwrap failed!\n");
        return 1;
    }

    printf("KW test passed ✅\n");
    return 0;
}
