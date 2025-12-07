import requests, time
from concurrent.futures import ThreadPoolExecutor

URL = "http://localhost:8000/check_transaction_batch"
BATCH_SIZE = 1000
N_REQUESTS = 20   # total 20 batch dikirim paralel

# bikin data dummy
def make_batch(i):
    return [{"account": "10042B8E8", "amount": (i * 1000 + j) * 1.1} for j in range(BATCH_SIZE)]

# fungsi untuk kirim request
def send_batch(i):
    batch = make_batch(i)
    r = requests.post(URL, json=batch, timeout=10)
    return r.status_code, len(batch)

# ukur waktu
t0 = time.time()
with ThreadPoolExecutor(max_workers=8) as ex:
    results = list(ex.map(send_batch, range(N_REQUESTS)))
elapsed = time.time() - t0

total_tx = N_REQUESTS * BATCH_SIZE
throughput = total_tx / elapsed

print(f"Total requests : {N_REQUESTS}")
print(f"Batch size     : {BATCH_SIZE}")
print(f"Total tx       : {total_tx}")
print(f"Elapsed time   : {elapsed:.3f}s")
print(f"Throughput     : {throughput:.2f} tx/s")
