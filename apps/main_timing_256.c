#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mach/mach_time.h>

#include "../include/aes_256.h"
#include "../include/key_expansion_256.h"
#include "../include/sbox.h"
#include "../include/aes_defs.h" // for AES-256 constants

#define NUM_REPEATS 10000  // Number of encryptions per test to amplify timing

uint64_t get_time_ns() {
    static mach_timebase_info_data_t info = {0};
    if (info.denom == 0) {
        mach_timebase_info(&info);
    }
    uint64_t t = mach_absolute_time();
    return t * info.numer / info.denom;
}

int main() {
    uint8_t key[AES256_KEY_SIZE] = {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
        0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
        0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    };

    uint8_t sbox[256];
    initialize_aes_sbox(sbox);

    uint8_t expanded_keys[AES256_EXPANDED_KEY_SIZE];
    aes256_key_expansion(key, expanded_keys, sbox);

    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];

    FILE *fp = fopen("timing.csv", "w");
    if (!fp) {
        perror("Failed to open timing.csv for writing");
        return 1;
    }

    fprintf(fp, "plaintext_byte,total_time_ns\n");

    for (int b = 0; b < 256; b++) {
        plaintext[0] = (uint8_t)b;

        uint64_t start = get_time_ns();

        for (int r = 0; r < NUM_REPEATS; r++) {
            aes256_encrypt_block(plaintext, ciphertext, expanded_keys, sbox);
        }

        uint64_t end = get_time_ns();

        fprintf(fp, "%d,%llu\n", b, (unsigned long long)(end - start));
    }

    fclose(fp);

    printf("Timing data written to timing.csv\n");
    return 0;
}
