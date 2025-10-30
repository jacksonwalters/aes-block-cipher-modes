#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "gmac.h"

#define MAX_BYTES 8192
#define MAX_LINE 8192

struct gmac_vector {
    uint8_t key[MAX_BYTES], iv[MAX_BYTES];
    uint8_t aad[MAX_BYTES];
    uint8_t tag[MAX_BYTES];
    size_t key_len, iv_len, aad_len, tag_len;
    int has_plaintext;
    int is_fail;  // Added: indicates this vector should fail authentication
};

/* Convert two hex chars to a byte */
static uint8_t hex_to_byte(const char *hex) {
    uint8_t hi = (uint8_t)((isdigit(hex[0]) ? hex[0]-'0' : tolower(hex[0])-'a'+10) & 0xF);
    uint8_t lo = (uint8_t)((isdigit(hex[1]) ? hex[1]-'0' : tolower(hex[1])-'a'+10) & 0xF);
    return (hi << 4) | lo;
}

/* Strip trailing whitespace */
static void strip_trailing(char *line) {
    size_t len = strlen(line);
    while (len > 0 && isspace((unsigned char)line[len-1])) {
        line[len-1] = 0;
        len--;
    }
}

/* Parse hex string into bytes */
static size_t parse_hex(const char *hex_str, uint8_t *out) {
    size_t out_pos = 0;
    size_t len = strlen(hex_str);
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)hex_str[i])) continue;
        if (i + 1 < len && isxdigit((unsigned char)hex_str[i+1])) {
            if (out) out[out_pos] = hex_to_byte(&hex_str[i]);
            out_pos++;
            i++;
        }
    }
    return out_pos;
}

/* Parse a single vector from a .rsp file */
static int parse_vector(FILE *f, struct gmac_vector *v) {
    char line[MAX_LINE];
    int has_key = 0;
    memset(v, 0, sizeof(*v));

    while (fgets(line, sizeof(line), f)) {
        strip_trailing(line);
        if (line[0] == 0 || line[0] == '#') continue;

        // Check for FAIL marker
        if (strncasecmp(line, "FAIL", 4) == 0) {
            v->is_fail = 1;
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = 0;
        char *name = line;
        char *value = eq + 1;

        while (*name && isspace((unsigned char)*name)) name++;
        char *name_end = name + strlen(name) - 1;
        while (name_end > name && isspace((unsigned char)*name_end)) *name_end-- = 0;
        while (*value && isspace((unsigned char)*value)) value++;

        if (strcasecmp(name, "Count") == 0) {
            if (has_key) {
                fseek(f, -(long)(strlen(line) + strlen(value) + 2), SEEK_CUR);
                return 1;
            }
        } else if (strcasecmp(name, "Key") == 0) {
            v->key_len = parse_hex(value, v->key);
            has_key = 1;
        } else if (strcasecmp(name, "IV") == 0) {
            v->iv_len = parse_hex(value, v->iv);
        } else if (strcasecmp(name, "PT") == 0) {
            size_t pt_len = parse_hex(value, NULL);
            v->has_plaintext = (pt_len > 0);
        } else if (strcasecmp(name, "AAD") == 0) {
            v->aad_len = parse_hex(value, v->aad);
        } else if (strcasecmp(name, "Tag") == 0) {
            v->tag_len = parse_hex(value, v->tag);
        }
    }

    return has_key;
}

/* Write hex data to file with label */
static void log_hex(FILE *log, const char *label, const uint8_t *data, size_t len) {
    fprintf(log, "%s = ", label);
    for (size_t i = 0; i < len; i++) fprintf(log, "%02X", data[i]);
    fprintf(log, "\n");
}

int main(void) {
    const char *files[] = {
        "test_vectors/gcmtestvectors/gcmDecrypt128.rsp",
        "test_vectors/gcmtestvectors/gcmDecrypt192.rsp",
        "test_vectors/gcmtestvectors/gcmDecrypt256.rsp",
        "test_vectors/gcmtestvectors/gcmEncryptExtIV128.rsp",
        "test_vectors/gcmtestvectors/gcmEncryptExtIV192.rsp",
        "test_vectors/gcmtestvectors/gcmEncryptExtIV256.rsp"
    };

    struct gmac_vector v;
    struct gmac_ctx ctx;
    int total_vectors = 0, total_passed = 0, total_skipped = 0;

    FILE *log = fopen("log/failed_gmac.log", "w");
    if (!log) { perror("log/failed_gmac.log"); return 1; }

    for (size_t fidx = 0; fidx < sizeof(files)/sizeof(files[0]); fidx++) {
        FILE *fp = fopen(files[fidx], "r");
        if (!fp) { perror(files[fidx]); continue; }

        int vector_count = 0, passed = 0, skipped = 0;

    while (parse_vector(fp, &v)) {
        // Only consider vectors with PTlen == 0 (no plaintext = GMAC mode)
        if (v.has_plaintext) continue;

        vector_count++;
        total_vectors++;

        if (v.key_len != 16 && v.key_len != 24 && v.key_len != 32) {
            skipped++;
            total_skipped++;
            continue;
        }

        if (gmac_init(&ctx, v.key, v.key_len, v.iv, v.iv_len) != 0) {
            skipped++;
            total_skipped++;
            continue;
        }

        uint8_t computed_tag[16];
        gmac_compute(&ctx, v.aad, v.aad_len, computed_tag, v.tag_len);

        int tags_match = (memcmp(computed_tag, v.tag, v.tag_len) == 0);

        // For FAIL vectors: pass if tags DON'T match (expected behavior)
        // For normal vectors: pass if tags DO match
        int test_passed = v.is_fail ? !tags_match : tags_match;

        if (!test_passed) {
            // Log the failing vector
            fprintf(log, "# Failure (Count=%d) in %s%s\n", 
                    vector_count, files[fidx], v.is_fail ? " [FAIL vector]" : "");
            log_hex(log, "Key", v.key, v.key_len);
            log_hex(log, "IV", v.iv, v.iv_len);
            if (v.aad_len) log_hex(log, "AAD", v.aad, v.aad_len);
            if (v.tag_len) {
                log_hex(log, "Tag_expected", v.tag, v.tag_len);
                log_hex(log, "Tag_actual", computed_tag, v.tag_len);
            }
            if (v.is_fail) {
                fprintf(log, "ERROR: FAIL vector produced matching tag (should mismatch)\n");
            }
            fprintf(log, "\n");
        } else {
            passed++;
            total_passed++;
        }
    }

        fclose(fp);
        int failed = vector_count - passed - skipped;
        printf("%-45s %5d total | %5d passed | %5d failed | %5d skipped\n", 
               files[fidx], vector_count, passed, failed, skipped);
    }

    fclose(log);

    printf("\n========================================\n");
    printf("Total: %d | Passed: %d | Failed: %d | Skipped: %d\n", 
           total_vectors, total_passed, total_vectors - total_passed - total_skipped, total_skipped);

    return (total_vectors == total_passed + total_skipped) ? 0 : 1;
}