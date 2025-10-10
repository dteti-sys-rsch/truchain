import pandas as pd

# ==== CONFIG ====
CSV_PATH = "raw.csv"          # file asli
OUTPUT_PATH = "filtered_100_700.csv"
LOWER = 100                   # batas bawah frekuensi transaksi
UPPER = 700                   # batas atas frekuensi transaksi

# ==== LOAD DATA ====
df = pd.read_csv(CSV_PATH, parse_dates=["Timestamp"])
print(f"📂 File '{CSV_PATH}' berhasil dibaca ({len(df):,} rows)")

# ==== HITUNG JUMLAH TRANSAKSI PER ACCOUNT ====
tx_count = df.groupby("Account").size().reset_index(name="Transaction Count")

# ==== PILIH AKUN DENGAN FREKUENSI DALAM RENTANG ====
selected_accounts = tx_count[
    (tx_count["Transaction Count"] > LOWER) & 
    (tx_count["Transaction Count"] < UPPER)
]["Account"]

print(f"✅ Ditemukan {len(selected_accounts)} akun dengan transaksi di antara {LOWER} dan {UPPER}")

# ==== FILTER DATAFRAME ====
df_filtered = df[df["Account"].isin(selected_accounts)]

print(f"📊 Total baris tersisa setelah filter: {len(df_filtered):,}")

# ==== SIMPAN HASIL ====
df_filtered.to_csv(OUTPUT_PATH, index=False)
print(f"💾 File hasil disimpan sebagai '{OUTPUT_PATH}'")
