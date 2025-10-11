CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -Iinclude -I../AES/aes128_c

# CTR sources
CTR_SRC = src/ctr.c src/aes_wrapper.c

# AES sources
AES_SRC = ../AES/aes128_c/aes.c ../AES/aes128_c/key_expansion.c ../AES/aes128_c/sbox.c

# Test
TEST_SRC = tests/test_ctr.c

all: test_ctr

test_ctr: $(CTR_SRC) $(AES_SRC) $(TEST_SRC)
	$(CC) $(CFLAGS) $(CTR_SRC) $(AES_SRC) $(TEST_SRC) -o test_ctr

clean:
	rm -f test_ctr *.o
