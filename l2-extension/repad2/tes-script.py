import requests, time

for i in range(10):
    t0 = time.time()
    r = requests.post("http://localhost:8000/check_transaction",
                      json={"account":"10042B7C8","amount":400000000})
    print(i, r.json(), f"{time.time()-t0:.3f}s")
