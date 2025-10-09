import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# ==== CONFIG ====
RAW_PATH = "filtered_100_700.csv"
ACCOUNT_ID = "10042B7C8"

# ==== LOAD DATA ====
df = pd.read_csv(RAW_PATH, parse_dates=["Timestamp"])
print(f"📂 File '{RAW_PATH}' berhasil dibaca ({len(df):,} rows)")

# ==== FILTER DATA AKUN ====
acc_df = df[df["Account"] == ACCOUNT_ID].sort_values("Timestamp")

if acc_df.empty:
    print(f"⚠️ Tidak ditemukan data untuk akun {ACCOUNT_ID}")
    exit()

print(f"✅ Akun {ACCOUNT_ID} memiliki {len(acc_df)} transaksi.\n")

# ==== HITUNG STATISTIK DASAR ====
amounts = pd.to_numeric(acc_df["Amount Received"], errors="coerce").to_numpy().reshape(-1)

stats = {
    "Min": np.nanmin(amounts),
    "Max": np.nanmax(amounts),
    "Mean": np.nanmean(amounts),
    "Median": np.nanmedian(amounts),
    "Std": np.nanstd(amounts),
    "Range": np.nanmax(amounts) - np.nanmin(amounts),
}
print("📊 Statistik Dasar:")
for k, v in stats.items():
    print(f"  - {k:<7}: {v:,.2f}")

# ==== PLOT TREND ====
plt.figure(figsize=(12,6))
plt.plot(acc_df["Timestamp"].to_numpy(), amounts, label="Nominal Transaksi", color="blue")

plt.title(f"📈 Tren Transaksi Akun {ACCOUNT_ID}")
plt.xlabel("Timestamp")
plt.ylabel("Amount Received (USD)")
plt.legend()
plt.grid(True, linestyle="--", alpha=0.5)
plt.tight_layout()
plt.show()
