import requests, time

# ==== Contoh batch transactions ====
batch = [
    {"account": "10042B7C8", "amount": 400_000_000},
    {"account": "10042B7C8", "amount": 10_000_000},
    {"account": "10042B7C8", "amount": 500_000_000},
    {"account": "10042B7C8", "amount": 2_000_000},
]

t0 = time.time()
r = requests.post("http://localhost:8000/check_transaction_batch", json=batch)
print(f"Batch processed in {time.time()-t0:.3f}s")

results = r.json()
for i, res in enumerate(results):
    print(i, res)
