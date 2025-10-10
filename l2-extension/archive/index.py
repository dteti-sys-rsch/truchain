import pandas as pd
import numpy as np
import json
import random

# === Load historical data ===
df = pd.read_csv("big.csv")
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['Amount'] = df['Amount Paid']

# === Compute per-account statistics ===
account_stats = df.groupby('Account')['Amount'].agg(['mean', 'std']).reset_index()
account_stats = account_stats.set_index('Account')

# Fill std=0 if only one transaction
account_stats['std'] = account_stats['std'].fillna(0.0).replace(0.0, 1e-6)  # avoid division by zero

# === Synthetic anomaly injection ===
n_injections = 1000
detected = 0
results = []

accounts = df['Account'].unique()
threshold_z = 3  # Z-score threshold

for _ in range(n_injections):
    # pilih akun secara acak
    acc = random.choice(accounts)
    stats = account_stats.loc[acc]
    avg_amount = stats['mean']
    std_amount = stats['std']

    # buat anomaly 50–100x lebih besar
    fake_amount = avg_amount * random.uniform(50, 100)

    # hitung Z-score
    z_score = (fake_amount - avg_amount) / std_amount

    flagged = abs(z_score) > threshold_z
    if flagged:
        detected += 1

    results.append({
        "account": acc,
        "fake_amount": float(fake_amount),
        "mean": float(avg_amount),
        "std": float(std_amount),
        "z_score": float(z_score),
        "flagged": bool(flagged)
    })

# === Detection rate ===
detection_rate = detected / n_injections
print(f"Synthetic Anomaly Detection Rate: {detection_rate:.4f} ({detected}/{n_injections})")

# === Save detailed results ===
with open("synthetic_anomaly_zscore_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("Detailed results saved to synthetic_anomaly_zscore_results.json")
