#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "padding.h"

static void test_pad_unpad_empty() {
    uint8_t in[1] = {0};
    uint8_t *p = NULL;
    size_t out_len = 0;

    int r = pkcs7_pad(in, 0, 16, &p, &out_len);
    assert(r == PADDING_OK);
    assert(out_len == 16);
    for (size_t i = 0; i < out_len; ++i) assert(p[i] == 16);
    free(p);

    uint8_t padded[16]; memset(padded, 16, 16);
    uint8_t *unp = NULL;
    size_t plain_len = 0;
    r = pkcs7_unpad(padded, 16, 16, &unp, &plain_len);
    assert(r == PADDING_OK);
    assert(plain_len == 0);
    free(unp);
}

static void test_partial_block() {
    uint8_t in[5] = {1,2,3,4,5};
    uint8_t *p = NULL;
    size_t out_len = 0;
    int r = pkcs7_pad(in, 5, 8, &p, &out_len);
    assert(r == PADDING_OK);
    assert(out_len == 8);
    for (size_t i = 5; i < 8; ++i) assert(p[i] == 3);

    uint8_t *unp = NULL;
    size_t plain_len = 0;
    r = pkcs7_unpad(p, out_len, 8, &unp, &plain_len);
    assert(r == PADDING_OK);
    assert(plain_len == 5);
    assert(memcmp(unp, in, 5) == 0);
    free(p); free(unp);
}

static void test_bad_padding() {
    uint8_t bad[16]; memset(bad, 5, 16); bad[15] = 2;
    uint8_t *unp = NULL;
    size_t plain_len = 0;
    int r = pkcs7_unpad(bad, 16, 16, &unp, &plain_len);
    assert(r == PADDING_ERR_INVALID);
}

int main(void) {
    test_pad_unpad_empty();
    test_partial_block();
    test_bad_padding();
    puts("padding tests: OK");
    return 0;
}
