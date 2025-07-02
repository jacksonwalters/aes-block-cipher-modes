import pandas as pd
import matplotlib.pyplot as plt

# Load timing data CSV
df = pd.read_csv("timing.csv")

# Basic scatter plot of timing vs. plaintext byte
plt.figure(figsize=(10, 6))
plt.scatter(df['plaintext_byte'], df['total_time_ns'], s=10, alpha=0.7)
plt.title("AES Encryption Timing vs Plaintext First Byte")
plt.xlabel("Plaintext byte (0-255)")
plt.ylabel("Total time for encryptions (ns)")
plt.grid(True)
plt.show()
