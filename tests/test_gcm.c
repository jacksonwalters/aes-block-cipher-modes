#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "gcm.h"

#define MAX_BYTES 8192
#define MAX_LINE 8192

struct gcm_vector {
    uint8_t key[MAX_BYTES], iv[MAX_BYTES];
    uint8_t pt[MAX_BYTES], aad[MAX_BYTES];
    uint8_t ct[MAX_BYTES], tag[MAX_BYTES];
    size_t key_len, iv_len, pt_len, aad_len, ct_len, tag_len;
    int is_fail;
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
            out[out_pos++] = hex_to_byte(&hex_str[i]);
            i++;
        }
    }
    return out_pos;
}

/* Parse a single vector from a .rsp file */
static int parse_vector(FILE *f, struct gcm_vector *v) {
    char line[MAX_LINE];
    int has_key = 0;

    memset(v, 0, sizeof(*v));

    while (fgets(line, sizeof(line), f)) {
        strip_trailing(line);
        if (line[0] == 0 || line[0] == '#') continue;

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
            v->pt_len = parse_hex(value, v->pt);
        } else if (strcasecmp(name, "AAD") == 0) {
            v->aad_len = parse_hex(value, v->aad);
        } else if (strcasecmp(name, "CT") == 0) {
            v->ct_len = parse_hex(value, v->ct);
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
        "gcmtestvectors/gcmDecrypt128.rsp",
        "gcmtestvectors/gcmDecrypt192.rsp",
        "gcmtestvectors/gcmDecrypt256.rsp",
        "gcmtestvectors/gcmEncryptExtIV128.rsp",
        "gcmtestvectors/gcmEncryptExtIV192.rsp",
        "gcmtestvectors/gcmEncryptExtIV256.rsp"
    };

    struct gcm_vector v;
    struct gcm_ctx ctx;
    int total_vectors = 0, total_passed = 0, total_skipped = 0;

    FILE *log = fopen("log/failed_vectors.log", "w");
    if (!log) { perror("log/failed_vectors.log"); return 1; }

    for (size_t fidx = 0; fidx < sizeof(files)/sizeof(files[0]); fidx++) {
        FILE *fp = fopen(files[fidx], "r");
        if (!fp) { perror(files[fidx]); continue; }

        int vector_count = 0, passed = 0, skipped = 0;

        while (parse_vector(fp, &v)) {
            vector_count++;
            total_vectors++;

            if (v.is_fail) {
                uint8_t decrypted[MAX_BYTES];
                int res = gcm_decrypt(&ctx, v.ct, v.ct_len, v.aad, v.aad_len, v.tag, v.tag_len, decrypted);
                if (res != 0) {
                    passed++;
                    total_passed++;
                }
                continue;
            }

            if (v.key_len != 16 && v.key_len != 24 && v.key_len != 32) {
                skipped++;
                total_skipped++;
                continue;
            }

            gcm_init(&ctx, v.key, v.key_len, v.iv, v.iv_len);

            uint8_t ciphertext[MAX_BYTES], computed_tag[16];
            gcm_encrypt(&ctx, v.pt, v.pt_len, v.aad, v.aad_len, ciphertext, computed_tag, v.tag_len);

            int ok = 1;
            if (v.ct_len > 0 && memcmp(ciphertext, v.ct, v.ct_len) != 0) ok = 0;
            if (v.tag_len > 0 && memcmp(computed_tag, v.tag, v.tag_len) != 0) ok = 0;

            uint8_t decrypted[MAX_BYTES];
            if (v.ct_len > 0) {
                if (gcm_decrypt(&ctx, ciphertext, v.ct_len, v.aad, v.aad_len, v.tag, v.tag_len, decrypted) != 0)
                    ok = 0;
                else if (memcmp(decrypted, v.pt, v.pt_len) != 0)
                    ok = 0;
            }

            if (!ok) {
                // Log the failing vector with expected vs actual
                fprintf(log, "# Failure (Count=%d) in %s\n", vector_count, files[fidx]);
                log_hex(log, "Key", v.key, v.key_len);
                log_hex(log, "IV", v.iv, v.iv_len);
                if (v.pt_len) log_hex(log, "PT", v.pt, v.pt_len);
                if (v.ct_len) log_hex(log, "CT", ciphertext, v.ct_len);
                if (v.tag_len) {
                    log_hex(log, "Tag_expected", v.tag, v.tag_len);
                    log_hex(log, "Tag_actual", computed_tag, v.tag_len);
                }
                fprintf(log, "Decrypted = ");
                for (size_t i = 0; i < v.pt_len; i++) fprintf(log, "%02X", decrypted[i]);
                fprintf(log, "\n\n");
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

    return (total_vectors == total_passed) ? 0 : 1;
}
