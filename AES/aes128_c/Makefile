# AES core Makefile
.PHONY: all test_aes clean

all: test_aes

test_aes: aes.c key_expansion.c sbox.c test_aes.c
	gcc -std=c11 -Wall -Wextra -O2 -I. -o test_aes test_aes.c aes.c key_expansion.c sbox.c

clean:
	rm -f test_aes
