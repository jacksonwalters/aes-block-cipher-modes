# AES/aes128_c/Makefile

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -I.

SRCS = aes.c key_expansion.c sbox.c
TEST = test_aes
TEST_SRCS = test_aes.c $(SRCS)

.PHONY: all clean

all: $(TEST)

$(TEST): $(TEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS)

clean:
	rm -f *.o $(TEST)
