#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>

#include "../include/ecb.h"
#include "../include/aes_wrapper.h"
#include "../include/aes_128.h"
#include "../include/key_expansion_128.h"
#include "../include/key_expansion_192.h"
#include "../include/key_expansion_256.h"
#include "../include/sbox.h"
#include "../include/padding.h"

/* ===============================
 *  Built-in sanity tests
 * =============================== */

static int test_nist_vector(void) {
    const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    const uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };

    const uint8_t expected_ciphertext[16] = {
        0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
    };

    uint8_t round_keys[176];
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16 };

    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};

    aes_ecb_encrypt(plaintext, ciphertext, 16, &ctx);
    aes_ecb_decrypt(ciphertext, decrypted, 16, &ctx);

    if (memcmp(ciphertext, expected_ciphertext, 16) != 0) return 1;
    if (memcmp(decrypted, plaintext, 16) != 0) return 2;
    return 0;
}

static int test_partial_block(void) {
    const uint8_t key[16] = {0};
    uint8_t round_keys[176], sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16 };

    uint8_t plaintext[5] = {1,2,3,4,5};
    uint8_t *cipher = NULL, *plain = NULL;
    size_t cipher_len = 0, plain_len = 0;

    if (aes_ecb_encrypt_padded(plaintext, 5, &ctx, &cipher, &cipher_len) != 0) return 1;
    if (aes_ecb_decrypt_padded(cipher, cipher_len, &ctx, &plain, &plain_len) != 0) return 2;

    if (plain_len != 5) return 3;
    if (memcmp(plain, plaintext, 5) != 0) return 4;

    free(cipher);
    free(plain);
    return 0;
}

static int test_empty(void) {
    const uint8_t key[16] = {0};
    uint8_t round_keys[176], sbox[256];
    initialize_aes_sbox(sbox);
    aes_key_expansion_128(key, round_keys, sbox);
    struct aes_ctx ctx = { .round_keys = round_keys, .sbox = sbox, .key_len = 16 };

    uint8_t *cipher = NULL, *plain = NULL;
    size_t cipher_len = 0, plain_len = 0;

    if (aes_ecb_encrypt_padded(NULL, 0, &ctx, &cipher, &cipher_len) != 0) return 1;
    if (aes_ecb_decrypt_padded(cipher, cipher_len, &ctx, &plain, &plain_len) != 0) return 2;

    if (plain_len != 0) return 3;

    free(cipher);
    free(plain);
    return 0;
}

/* ===============================
 *  AESAVS ECB Vector Parsing
 * =============================== */

struct ecb_vector {
    uint8_t key[32];
    uint8_t input[32];
    uint8_t expected[32];
    size_t key_len;
    size_t data_len;
    int encrypt;  // 1 = encrypt, 0 = decrypt
};

static int parse_hex(const char *hex, uint8_t *out) {
    size_t len = strlen(hex);
    for (size_t i = 0; i < len / 2; i++)
        sscanf(hex + 2*i, "%2hhx", &out[i]);
    return (int)(len / 2);
}

static int load_ecb_vectors(const char *path, struct ecb_vector **out, size_t *count) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    struct ecb_vector *vecs = NULL;
    size_t cap = 0, n = 0;
    char line[256];
    int mode = 1;  // 1=encrypt, 0=decrypt

    struct ecb_vector v = {0};

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

static int run_ecb_vector_tests(const char *path) {
    struct ecb_vector *vecs = NULL;
    size_t count = 0;
    if (load_ecb_vectors(path, &vecs, &count) != 0) {
        fprintf(stderr, "Failed to load ECB vectors from %s\n", path);
        return 1;
    }

    uint8_t round_keys[240], sbox[256];
    initialize_aes_sbox(sbox);

    for (size_t i = 0; i < count; i++) {
        struct ecb_vector *v = &vecs[i];
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

        if (v->encrypt)
            aes_ecb_encrypt(v->input, out, v->data_len, &ctx);
        else
            aes_ecb_decrypt(v->input, out, v->data_len, &ctx);

        if (memcmp(out, v->expected, v->data_len) != 0) {
            fprintf(stderr, "ECB vector %zu FAILED (%s)\n", i, v->encrypt ? "encrypt" : "decrypt");
            free(vecs);
            return 1;
        }
    }

    printf("All ECB CAVP vectors passed (%zu cases) — %s\n", count, path);
    free(vecs);
    return 0;
}

/* ===============================
 *  Run All Known Answer Tests
 * =============================== */

static void run_all_ecb_vectors(void) {
    const char *kat_dir = "test_vectors/KAT_AES";
    const char *patterns[] = {
        "ECBVarTxt128.rsp", "ECBVarKey128.rsp", "ECBKeySbox128.rsp",
        "ECBVarTxt192.rsp", "ECBVarKey192.rsp", "ECBKeySbox192.rsp",
        "ECBVarTxt256.rsp", "ECBVarKey256.rsp", "ECBKeySbox256.rsp",
        NULL
    };

    for (int i = 0; patterns[i]; ++i) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", kat_dir, patterns[i]);
        printf("\n== Running %s ==\n", path);
        if (run_ecb_vector_tests(path) != 0)
            fprintf(stderr, "ECB vector test failed for %s\n", path);
    }
}

/* ===============================
 *  Main
 * =============================== */

int main(void) {
    if (test_nist_vector() != 0) { fprintf(stderr, "NIST ECB test FAILED\n"); return 1; }
    if (test_partial_block() != 0) { fprintf(stderr, "Partial-block ECB test FAILED\n"); return 2; }
    if (test_empty() != 0) { fprintf(stderr, "Empty ECB test FAILED\n"); return 3; }

    run_all_ecb_vectors();

    printf("\nAll ECB tests passed.\n");
    return 0;
}