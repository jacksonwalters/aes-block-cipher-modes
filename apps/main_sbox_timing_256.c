#include <stdio.h>
#include <stdint.h>

#include "../include/sbox.h"  // make sure this declares initialize_aes_sbox and sbox array

#define NUM_REPEATS 1000000  // Repeat enough times for measurable timing

#ifdef __APPLE__
#include <mach/mach_time.h>
uint64_t get_time_ns() {
    static mach_timebase_info_data_t info = {0};
    if (info.denom == 0) {
        mach_timebase_info(&info);
    }
    uint64_t t = mach_absolute_time();
    return t * info.numer / info.denom;
}
#else
#include <time.h>
uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

int main() {
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);

    FILE *fp = fopen("data/sbox_timing.csv", "w");
    if (!fp) {
        perror("Failed to open data/sbox_timing.csv for writing");
        return 1;
    }

    fprintf(fp, "input_byte,total_time_ns\n");

    for (int b = 0; b < 256; b++) {
        uint8_t val;
        uint64_t start = get_time_ns();

        // Repeat S-box lookup many times to amplify timing differences
        for (int r = 0; r < NUM_REPEATS; r++) {
            val = sbox[(uint8_t)b];
            (void)val; // prevent compiler optimization
        }

        uint64_t end = get_time_ns();
        fprintf(fp, "%d,%llu\n", b, (unsigned long long)(end - start));
    }

    fclose(fp);
    printf("S-box timing data written to data/sbox_timing.csv\n");
    return 0;
}
