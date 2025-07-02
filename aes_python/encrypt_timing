import time
import csv
from aes import aes_encrypt_block

def timing_test(key_bytes, plaintext_bytes, iterations=1000):
    # Warm-up
    for _ in range(100):
        aes_encrypt_block(plaintext_bytes, key_bytes)

    start = time.perf_counter()
    for _ in range(iterations):
        aes_encrypt_block(plaintext_bytes, key_bytes)
    end = time.perf_counter()

    total_time = end - start
    avg_time_ns = (total_time / iterations) * 1e9
    return avg_time_ns

def vary_key_byte_and_time(byte_pos=0, iterations=1000, key_length=16):
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    # Start with all-zero key
    base_key = bytearray([0]*key_length)

    results = []
    print(f"Timing AES encryptions varying byte {byte_pos} of the key...")

    for byte_val in range(256):
        base_key[byte_pos] = byte_val
        avg_time = timing_test(bytes(base_key), plaintext, iterations)
        results.append((byte_pos, byte_val, avg_time))
        if byte_val % 32 == 0:
            print(f"Byte {byte_pos} = {byte_val:02x}: {avg_time:.2f} ns")

    return results

def main():
    # Choose which byte to vary (0-15 for AES-128, 0-31 for AES-256)
    byte_to_vary = 0
    key_len = 16  # or 32 for AES-256
    iterations = 1000

    results = vary_key_byte_and_time(byte_to_vary, iterations, key_len)

    # Save to CSV
    csv_file = "timing_results.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["byte_position", "byte_value", "avg_time_ns"])
        writer.writerows(results)

    print(f"\nTiming results saved to {csv_file}")
    print("Sample output (first 10 lines):")
    for row in results[:10]:
        print(f"Byte pos {row[0]}, Value {row[1]:02x}, Avg Time {row[2]:.2f} ns")

if __name__ == "__main__":
    main()
