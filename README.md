# AES, block cipher standards

[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)
![basic tests](https://github.com/jacksonwalters/aes-block-cipher-standards/actions/workflows/build.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-92.7%25-brightgreen)

This repository implements several cryptographic standards in C. 

Primarily, different modes of AES from NIST Special Publication 800-38X. 

[https://csrc.nist.gov/pubs/sp/800/38/a/final](https://csrc.nist.gov/pubs/sp/800/38/a/final)

AES is also implemented in Python to simulate timing attacks by looking at S-box leakage.

## Disclaimer

They are not resistant to side-channel attacks, nor necessarily performant. They are primarily for educational use.

## Build

To build the binaries, run:

```
make
```

The binaries will be in `bin`. For example, one could run:

```
./bin/main_128
```

To run some examples with AES-128.

## Test

To run the suite of tests, run:

```
make test
```

## Advanced Encryption Standard (AES)

- [x] [FIPS 197 (2001), i.e. AES](#aes)

## NIST Block Cipher Modes (SP 800-38x Series)

- [x] **SP 800-38A** — Block Cipher Modes of Operation  
  - ECB (Electronic Codebook)  
  - CBC (Cipher Block Chaining)  
  - CFB (Cipher Feedback)  
  - OFB (Output Feedback)
  - CTR (Counter Mode)

- [x] **SP 800-38B** — CMAC (Cipher-based Message Authentication Code)

- [x] **SP 800-38C** — CCM (Counter with CBC-MAC)

- [x] **SP 800-38D** — GCM and GMAC (Galois/Counter Mode)

- [x] **SP 800-38E** — XTS (XEX-based Tweaked CodeBook mode with CipherText Stealing)

- [x] **SP 800-38F** — Modes for Key Wrapping

---

## NIST Algorithm Validation & Reference Docs

- [ ] **CAVP Test Vectors** — Implement test harness to verify correctness  
- [ ] **CMVP** — (Optional) Integrate self-tests / validation reporting

---

## Protocol and Standards Integration

- [ ] **RFC 5116** — AEAD (Authenticated Encryption with Associated Data) interface  
- [ ] **RFC 5288** — AES-GCM Cipher Suites for TLS

- [ ] **ISO/IEC JTC 1 SC 27** — High-level review of ISO crypto standards (for comparison and interoperability)

- [ ] **ANSI X9F** — Financial crypto standards (e.g., Triple DES modes, MACing) — optional stretch goal

- [ ] **IEEE Standards** — Optional reference (e.g., secure hardware, P1619 XTS mode)

---

## Additional Tools & Techniques (Implementation Side)

- [x] Implement padding (PKCS#7) and ciphertext stealing (CTS)  
- [ ] Write reusable AES primitive to support all modes  
- [ ] Add unit tests for each mode (including edge cases)  
- [ ] Integrate CAVP test vectors for validation  
- [ ] Build benchmarking harness (performance & correctness)  
- [ ] Add error handling and misuse detection (e.g., nonce reuse detection in GCM)

---

## AES

### Implementation

This repository implements basic implementations of AES128 and AES256 in C, Python. 

The core algorithm proceeds by performing S-box, shift, mix, and add_round methods. 

- sub_bytes(state, sbox);
- shift_rows(state);
- mix_columns(state);
- add_round_key(state, round_keys + round * AES256_BLOCK_SIZE);

These are permutation and substituions methods performed on a block which is length 16 consisting of `uint8` bytes. These can be viewed as polynomials in `GF(2^8)`.

### Timing

For each possible value of the first plaintext byte (0x00 to 0xFF):
- Fills the 16-byte AES input block with all zeros except the first byte set to that value.
- runs AES encryption many times (e.g., 10,000) on that same block, measuring the total time taken.
- Records the total elapsed time for these encryptions.
- Outputs a CSV where each line corresponds to a plaintext first byte value and the total time to encrypt 10,000 blocks with that first byte.

---
