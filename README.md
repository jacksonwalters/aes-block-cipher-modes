**Implementation**

This repository implements basic implementations of AES128 and AES256 in C, Python. 

The core algorithm proceeds by performing S-box, shift, mix, and add_round methods. 

- sub_bytes(state, sbox);
- shift_rows(state);
- mix_columns(state);
- add_round_key(state, round_keys + round * AES256_BLOCK_SIZE);

These are permutation and substituions methods performed on a block which is length 16 consisting of `uint8` bytes. These can be viewed as polynomials in `GF(2^8)`.

**Timing**

For each possible value of the first plaintext byte (0x00 to 0xFF):
- Fills the 16-byte AES input block with all zeros except the first byte set to that value.
- runs AES encryption many times (e.g., 10,000) on that same block, measuring the total time taken.
- Records the total elapsed time for these encryptions.
- Outputs a CSV where each line corresponds to a plaintext first byte value and the total time to encrypt 10,000 blocks with that first byte.

**Usage**

To compile: `gcc -Wall -Wextra -O2 -o timing main_timing.c aes256.c key_expansion.c sbox.c`

This produces a `timing.csv` file consisting of the time it takes to encode a single byte averaged over 10,000 runs. 

One can view this plot with the Python code: `python plot_timing.py`
