# AES-CBC Makefile
.PHONY: all test_cbc clean

all: test_cbc

test_cbc: src/cbc.c src/aes_wrapper.c ../AES/aes128_c/aes.c ../AES/aes128_c/key_expansion.c ../AES/aes128_c/sbox.c tests/test_cbc.c
	gcc -std=c11 -Wall -Wextra -O2 -Iinclude -I../AES/aes128_c \
	    src/cbc.c src/aes_wrapper.c ../AES/aes128_c/aes.c ../AES/aes128_c/key_expansion.c ../AES/aes128_c/sbox.c \
	    tests/test_cbc.c -o test_cbc

clean:
	rm -f test_cbc
