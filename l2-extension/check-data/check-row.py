import pandas as pd

# ==== CONFIG ====
CSV_PATH = "filtered_over_100.csv"  # ganti kalau nama file lo beda

# ==== LOAD DATA ====
df = pd.read_csv(CSV_PATH, parse_dates=["Timestamp"])

# ==== INFO DASAR ====
total_rows = len(df)
total_accounts = df["Account"].nunique()

print(f"📂 File '{CSV_PATH}' berhasil dibaca.")
print(f"📊 Total baris data       : {total_rows}")
print(f"👥 Total akun unik         : {total_accounts}\n")

# ==== HITUNG JUMLAH TRANSAKSI PER ACCOUNT ====
tx_count = df.groupby("Account").size().reset_index(name="Transaction Count")

# ==== URUTKAN DARI YANG SEDIKIT ====
tx_count_sorted = tx_count.sort_values("Transaction Count", ascending=True)

# ==== TAMPILKAN 10 ACCOUNT TERENDAH DAN TERTINGGI ====
print("🔽 10 akun dengan transaksi paling sedikit:")
print(tx_count_sorted.head(10).to_string(index=False))

print("\n🔼 10 akun dengan transaksi terbanyak:")
print(tx_count_sorted.tail(10).to_string(index=False))

# ==== OPSIONAL: SIMPAN KE FILE CSV ====
tx_count_sorted.to_csv("transaction_count_per_account.csv", index=False)
print("\n✅ File hasil disimpan sebagai 'transaction_count_per_account.csv'")
