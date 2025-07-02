import pandas as pd
import matplotlib.pyplot as plt
import sys

# Allow filename as a command-line argument
if len(sys.argv) < 2:
    print("Usage: python plot_timing.py <csv_file>")
    sys.exit(1)

filename = sys.argv[1]

# Load CSV
df = pd.read_csv(filename)

# Determine column names based on file type
if 'plaintext_byte' in df.columns:
    x_col = 'plaintext_byte'
    title = "AES Encryption Timing vs Plaintext First Byte"
elif 'input_byte' in df.columns:
    x_col = 'input_byte'
    title = "S-box Lookup Timing vs Input Byte"
else:
    print("Error: Unrecognized CSV format")
    sys.exit(1)

# Plot
plt.figure(figsize=(10, 6))
plt.scatter(df[x_col], df['total_time_ns'], s=10, alpha=0.7)
plt.title(title)
plt.xlabel(f"{x_col.replace('_', ' ').capitalize()} (0-255)")
plt.ylabel("Total time (ns)")
plt.grid(True)
plt.show()

