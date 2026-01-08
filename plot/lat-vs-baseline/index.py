import matplotlib.pyplot as plt
import numpy as np


# Data
latency = [50, 77, 116, 124, 143, 144, 150, 151, 160, 165, 168, 169, 169, 185, 188, 219, 221, 222, 224, 258, 965]
labels = ["Danske Bank", "Mettle", "AIB (UK)", "Barclays", "Nationwide Building Society", "First Direct",
           "HSBC Kinetic", "HSBC Business", "AIB (NI)", "HSBC Personal", "NWB", "Bank of Ireland (UK)",
           "TruChain", "HSBC Kinetic", "UBN", "Bank of Scotland", "Halifax", "Lloyds", "MBNA", "RBS", "Coutts"]

plt.figure(figsize=(6, 6))

colors = ["#6986ce"] * len(latency)
# Change TruChain color to darker blue
colors[12] = "#2f5597"

bars = plt.bar(labels, latency, color=colors)

plt.ylabel("Latency (ms)", fontsize=12)
plt.xticks(rotation=45, ha='right', fontsize=12)
plt.grid(axis='y', linestyle='--', alpha=0.6)

plt.tight_layout()
plt.savefig("lat-vs-baseline.pdf", format="pdf", bbox_inches="tight")
