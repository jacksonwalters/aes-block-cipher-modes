# AES-CTR Makefile
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -Iinclude -I../AES/aes128_c

SRC = src/ctr.c src/aes_wrapper.c ../AES/aes128_c/aes.c ../AES/aes128_c/key_expansion.c ../AES/aes128_c/sbox.c
TEST = tests/test_ctr.c
OUT = test_ctr

all: $(OUT)

$(OUT): $(SRC) $(TEST)
	$(CC) $(CFLAGS) $(SRC) $(TEST) -o $(OUT)

clean:
	rm -f $(OUT) *.o
