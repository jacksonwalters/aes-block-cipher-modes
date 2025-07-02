import csv
import matplotlib.pyplot as plt

def read_timing_csv(filename):
    byte_values = []
    times_ns = []
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            byte_values.append(int(row['byte_value']))
            times_ns.append(float(row['avg_time_ns']))
    return byte_values, times_ns

def plot_timing(byte_values, times_ns, byte_pos):
    plt.figure(figsize=(10, 6))
    plt.plot(byte_values, times_ns, marker='o', linestyle='-', color='blue')
    plt.title(f'AES Encryption Timing Variation by Key Byte {byte_pos}')
    plt.xlabel('Key Byte Value (0x00 to 0xFF)')
    plt.ylabel('Avg Encryption Time (ns)')
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    filename = "timing_results.csv"
    byte_pos = 0  # update if you test a different byte position
    byte_values, times_ns = read_timing_csv(filename)
    plot_timing(byte_values, times_ns, byte_pos)
