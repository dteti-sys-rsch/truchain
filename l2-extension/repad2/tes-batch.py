import requests, time

# ==== Parameter batch ====
BATCH_SIZE = 200

# ==== Generate otomatis 200 akun ====
batch = [{"account": "10042B8E8", "amount": (i + 1) * 1000} for i in range(BATCH_SIZE)]

# ==== Hitung waktu eksekusi ====
t0 = time.time()
r = requests.post("http://localhost:8000/check_transaction_batch", json=batch)
elapsed = time.time() - t0

# ==== Hasil ====
print(f"Batch size     : {BATCH_SIZE}")
print(f"Elapsed time   : {elapsed:.3f}s")
print(f"Throughput     : {BATCH_SIZE / elapsed:.2f} tx/s")

# ==== (Opsional) Print sebagian hasil ====
try:
    results = r.json()
    print(f"Response status: {r.status_code}")
    print("First 3 results:", results[:3])
except Exception as e:
    print("Failed to parse JSON:", e)
    print("Raw response:", r.text[:200])
