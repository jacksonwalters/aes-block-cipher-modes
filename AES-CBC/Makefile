CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -Iinclude -I../AES/aes128_c

SRC = src/cbc.c src/aes_wrapper.c ../AES/aes128_c/aes.c ../AES/aes128_c/key_expansion.c ../AES/aes128_c/sbox.c
TEST = tests/test_cbc.c
TARGET = test_cbc

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(SRC) $(TEST) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o
