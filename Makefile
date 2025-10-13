# Top-level Makefile

.PHONY: all aes ctr cbc test clean

all: aes ctr cbc

aes:
	$(MAKE) -C AES/aes128_c test_aes

ctr:
	$(MAKE) -C AES-CTR test_ctr

cbc:
	$(MAKE) -C AES-CBC test_cbc

# New target to run all tests
test: aes ctr cbc
	@echo
	@echo "Running AES core test..."
	@./AES/aes128_c/test_aes
	@echo
	@echo "Running AES-CTR test..."
	@./AES-CTR/test_ctr
	@echo
	@echo "Running AES-CBC test..."
	@./AES-CBC/test_cbc
	@echo
	@echo "All tests completed."

clean:
	$(MAKE) -C AES/aes128_c clean
	$(MAKE) -C AES-CTR clean
	$(MAKE) -C AES-CBC clean
