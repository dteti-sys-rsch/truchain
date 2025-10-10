import pandas as pd

# ==== CONFIG ====
CSV_PATH = "raw.csv"  # file asli
OUTPUT_PATH = "filtered_over_100.csv"
THRESHOLD = 100  # batas frekuensi transaksi

# ==== LOAD DATA ====
df = pd.read_csv(CSV_PATH, parse_dates=["Timestamp"])
print(f"📂 File '{CSV_PATH}' berhasil dibaca ({len(df):,} rows)")

# ==== HITUNG JUMLAH TRANSAKSI PER ACCOUNT ====
tx_count = df.groupby("Account").size().reset_index(name="Transaction Count")

# ==== PILIH AKUN DENGAN FREKUENSI > 100 ====
active_accounts = tx_count[tx_count["Transaction Count"] > THRESHOLD]["Account"]
print(f"✅ Ditemukan {len(active_accounts)} akun dengan transaksi > {THRESHOLD}")

# ==== FILTER DATAFRAME ====
df_filtered = df[df["Account"].isin(active_accounts)]

print(f"📊 Total baris tersisa setelah filter: {len(df_filtered):,}")

# ==== SIMPAN HASIL ====
df_filtered.to_csv(OUTPUT_PATH, index=False)
print(f"💾 File hasil disimpan sebagai '{OUTPUT_PATH}'")
