# AES-CTR Makefile
.PHONY: all test_ctr clean

all: test_ctr

test_ctr: src/ctr.c src/aes_wrapper.c ../AES/aes128_c/aes.c ../AES/aes128_c/key_expansion.c ../AES/aes128_c/sbox.c tests/test_ctr.c
	gcc -std=c11 -Wall -Wextra -O2 -Iinclude -I../AES/aes128_c \
	    src/ctr.c src/aes_wrapper.c ../AES/aes128_c/aes.c ../AES/aes128_c/key_expansion.c ../AES/aes128_c/sbox.c \
	    tests/test_ctr.c -o test_ctr

clean:
	rm -f test_ctr
