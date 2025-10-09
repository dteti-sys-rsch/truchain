import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ==== CONFIG ====
SAVE_DIR = "experiment/repad2_models"
THRESH_SIGMA = 1.5
WINDOW_SIZE = 1000

df = pd.read_csv("filtered_100_700.csv", parse_dates=["Timestamp"])

def analyze_account_behavior(account_id, df):
    """
    Analisis perilaku akun individual berdasarkan hasil RePAD2.
    Menampilkan pola nominal, distribusi error (AARE), dan threshold RePAD2.
    """
    # Ambil data akun dari DataFrame
    acc_data = df[df["Account"] == account_id].sort_values("Timestamp")
    if acc_data.empty:
        print(f"⚠️ Akun {account_id} tidak ditemukan di dataset.")
        return

    # Load hasil RePAD2 (AARE window)
    aare_path = f"{SAVE_DIR}/aare_window_{account_id}.npy"
    if not os.path.exists(aare_path):
        print(f"⚠️ Tidak ada data RePAD2 untuk akun {account_id} (belum dilatih).")
        return

    AAREs = np.load(aare_path)
    mu, sigma = np.mean(AAREs), np.std(AAREs)
    threshold = np.clip(mu + THRESH_SIGMA * sigma, 0, 1)

    # Ambil data nominal
    nominal = acc_data["Amount Received"].values
    timestamps = acc_data["Timestamp"].values
    nominal_log = np.log1p(nominal)

    # --- Plot 1: Nominal Transaksi ---
    plt.figure(figsize=(12, 5))
    plt.plot(timestamps, nominal, color="blue", label="Nominal (Raw)")
    plt.title(f"[{account_id}] Transaksi Nominal")
    plt.xlabel("Timestamp")
    plt.ylabel("Amount")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # --- Plot 2: Log Nominal ---
    plt.figure(figsize=(12, 5))
    plt.plot(timestamps, nominal_log, color="purple", label="Nominal (log1p)")
    plt.title(f"[{account_id}] Transaksi Nominal (Log Scale)")
    plt.xlabel("Timestamp")
    plt.ylabel("log(Amount+1)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # --- Plot 3: AARE vs Threshold ---
    plt.figure(figsize=(12, 5))
    plt.plot(AAREs, color="green", label="AARE")
    plt.axhline(y=threshold, color="red", linestyle="--", label=f"Threshold ({threshold:.3f})")
    plt.title(f"[{account_id}] RePAD2 Error (AARE) vs Threshold")
    plt.xlabel("Transaction Index")
    plt.ylabel("AARE")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # --- Print summary ---
    mean_aare = np.mean(AAREs)
    std_aare = np.std(AAREs)
    pct_anomaly = np.sum(AAREs > threshold) / len(AAREs) * 100

    print(f"📊 SUMMARY [{account_id}]")
    print(f"- Mean AARE      : {mean_aare:.4f}")
    print(f"- Std AARE       : {std_aare:.4f}")
    print(f"- Threshold (μ+{THRESH_SIGMA}σ): {threshold:.4f}")
    print(f"- Anomaly Ratio  : {pct_anomaly:.2f}% of points flagged")

    # Return summary dict (optional)
    return {
        "Account": account_id,
        "Mean_AARE": mean_aare,
        "Std_AARE": std_aare,
        "Threshold": threshold,
        "Anomaly_Ratio": pct_anomaly
    }

analyze_account_behavior("10042B7C8", df)