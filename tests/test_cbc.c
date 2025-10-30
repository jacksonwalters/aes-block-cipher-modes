#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../include/cbc.h"
#include "../include/aes_wrapper.h"
#include "../include/aes_128.h"
#include "../include/aes_192.h"
#include "../include/aes_256.h"
#include "../include/key_expansion_128.h"
#include "../include/key_expansion_192.h"
#include "../include/key_expansion_256.h"
#include "../include/sbox.h"
#include "../include/padding.h"

/* ===============================
 *  Helper functions
 * =============================== */
static int parse_hex(const char *hex, uint8_t *out) {
    size_t len = strlen(hex);
    for (size_t i = 0; i < len / 2; i++)
        sscanf(hex + 2*i, "%2hhx", &out[i]);
    return (int)(len / 2);
}

/* ===============================
 *  Built-in sanity tests (padded CBC)
 * =============================== */
static int test_partial_block(void) {
    const uint8_t key[16] = {0};
    uint8_t round_keys[176], sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16 };

    uint8_t pt[5] = {1,2,3,4,5};
    size_t ct_len = 0, rec_len = 0;
    uint8_t iv[16] = {0};

    size_t buf_len = 16 * ((5 + 15) / 16);
    uint8_t *ct = malloc(buf_len);
    uint8_t *recovered = malloc(buf_len);
    if (!ct || !recovered) { free(ct); free(recovered); return 1; }

    int ret = aes_cbc_encrypt_padded(pt, 5, ct, &ct_len, iv, aes_block_wrapper, &ctx);
    if (ret == 0)
        ret = aes_cbc_decrypt_padded(ct, ct_len, recovered, &rec_len, iv, aes_block_wrapper_dec, &ctx);

    int ok = (ret == 0 && rec_len == 5 && memcmp(recovered, pt, 5) == 0);
    free(ct); free(recovered);
    return ok ? 0 : 2;
}

static int test_empty(void) {
    const uint8_t key[16] = {0};
    uint8_t round_keys[176], sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16 };

    size_t ct_len = 0, rec_len = 0;
    uint8_t iv[16] = {0};

    uint8_t *ct = malloc(16);
    uint8_t *recovered = malloc(16);
    if (!ct || !recovered) { free(ct); free(recovered); return 1; }

    int ret = aes_cbc_encrypt_padded(NULL, 0, ct, &ct_len, iv, aes_block_wrapper, &ctx);
    if (ret == 0)
        ret = aes_cbc_decrypt_padded(ct, ct_len, recovered, &rec_len, iv, aes_block_wrapper_dec, &ctx);

    int ok = (ret == 0 && rec_len == 0);
    free(ct); free(recovered);
    return ok ? 0 : 2;
}

/* ===============================
 *  AESAVS CBC Vector Parsing (unpadded CBC)
 * =============================== */
struct cbc_vector {
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t input[32];
    uint8_t expected[32];
    size_t key_len;
    size_t data_len;
    int encrypt;  // 1 = encrypt, 0 = decrypt
};

static int load_cbc_vectors(const char *path, struct cbc_vector **out, size_t *count) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    struct cbc_vector *vecs = NULL;
    size_t cap = 0, n = 0;
    char line[256];
    int mode = 1;
    struct cbc_vector v = {0};

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "[ENCRYPT]", 9) == 0) { mode = 1; continue; }
        if (strncmp(line, "[DECRYPT]", 9) == 0) { mode = 0; continue; }
        if (strncmp(line, "COUNT", 5) == 0) { memset(&v, 0, sizeof(v)); v.encrypt = mode; continue; }

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = '\0';
        while (*eq == ' ' || *eq == '\t') eq++;
        eq[strcspn(eq, "\r\n")] = 0;

        if (strncmp(line, "KEY", 3) == 0) v.key_len = parse_hex(eq, v.key);
        else if (strncmp(line, "IV", 2) == 0) parse_hex(eq, v.iv);
        else if (strncmp(line, "PLAINTEXT", 9) == 0) v.data_len = parse_hex(eq, v.input);
        else if (strncmp(line, "CIPHERTEXT", 10) == 0) {
            parse_hex(eq, v.expected);
            if (n >= cap) {
                cap = cap ? cap * 2 : 64;
                vecs = realloc(vecs, cap * sizeof(*vecs));
            }
            vecs[n++] = v;
        }
    }

    fclose(f);
    *out = vecs;
    *count = n;
    return 0;
}

static int run_cbc_vector_tests(const char *path) {
    struct cbc_vector *vecs = NULL;
    size_t count = 0;
    if (load_cbc_vectors(path, &vecs, &count) != 0) {
        fprintf(stderr, "Failed to load CBC vectors from %s\n", path);
        return 1;
    }

    uint8_t round_keys[240], sbox[256];
    initialize_aes_sbox(sbox);

    for (size_t i = 0; i < count; i++) {
        struct cbc_vector *v = &vecs[i];
        if (v->key_len == 0) continue;

        if (v->key_len == 16)
            aes_key_expansion_128(v->key, round_keys, sbox);
        else if (v->key_len == 24)
            aes_key_expansion_192(v->key, round_keys, sbox);
        else if (v->key_len == 32)
            aes_key_expansion_256(v->key, round_keys, sbox);
        else
            continue;

        struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = v->key_len };
        uint8_t out[32] = {0};
        uint8_t iv[16];
        memcpy(iv, v->iv, 16);

        size_t out_len = 0;
        int ret;
        if (v->encrypt)
            ret = aes_cbc_encrypt_unpadded(v->input, v->data_len, out, &out_len, iv, aes_block_wrapper, &ctx);
        else
            ret = aes_cbc_decrypt_unpadded(v->input, v->data_len, out, &out_len, iv, aes_block_wrapper_dec, &ctx);

        if (ret != 0 || memcmp(out, v->expected, v->data_len) != 0) {
            fprintf(stderr, "CBC vector %zu FAILED (%s)\n", i, v->encrypt ? "encrypt" : "decrypt");
            free(vecs);
            return 1;
        }
    }

    printf("All CBC CAVP vectors passed (%zu cases) — %s\n", count, path);
    free(vecs);
    return 0;
}

static int run_all_cbc_vectors(void) {
    const char *kat_dir = "test_vectors/KAT_AES";
    const char *patterns[] = {
        "CBCVarTxt128.rsp", "CBCVarKey128.rsp", "CBCKeySbox128.rsp",
        "CBCVarTxt192.rsp", "CBCVarKey192.rsp", "CBCKeySbox192.rsp",
        "CBCVarTxt256.rsp", "CBCVarKey256.rsp", "CBCKeySbox256.rsp",
        NULL
    };

    for (int i = 0; patterns[i]; ++i) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", kat_dir, patterns[i]);
        printf("\n== Running %s ==\n", path);
        if (run_cbc_vector_tests(path) != 0) {
            fprintf(stderr, "CBC vector test failed for %s\n", path);
            return 1;
        }
    }
    return 0;
}

/* ===============================
 *  Main
 * =============================== */
int main(void) {
    if (test_partial_block() != 0) { fprintf(stderr, "Partial-block CBC test FAILED\n"); return 1; }
    if (test_empty() != 0) { fprintf(stderr, "Empty CBC test FAILED\n"); return 2; }

    if (run_all_cbc_vectors() != 0) {
        fprintf(stderr, "\nSome CBC vector tests failed.\n");
        return 3;
    }

    printf("\nAll CBC tests passed.\n");
    return 0;
}
