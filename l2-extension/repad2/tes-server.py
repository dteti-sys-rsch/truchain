# server_fixed_threshold.py
import os
from typing import List
import numpy as np
import joblib
from tensorflow.keras.models import load_model
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from collections import deque, defaultdict
import threading

WINDOW_SIZE = 1000
THRESH_SIGMA = 1.5
SAVE_DIR = "experiment/repad2_models"
EPS = 1e-8

app = FastAPI(title="High-Perf Transaction Anomaly API - Fixed Threshold")

# ==== REQUEST MODEL ====
class TransactionRequest(BaseModel):
    account: str
    amount: float

# ==== GLOBAL CACHES ====
MODEL_CACHE = {}
SCALER_CACHE = {}
WINDOW_CACHE = {}
AARE_CACHE = {}
STAT_LOCK = defaultdict(threading.Lock)

# ==== RUNNING STAT CLASS (untuk inisialisasi threshold) ====
class RunningStat:
    def __init__(self, window_size):
        self.window = deque(maxlen=window_size)
        self.mean = 0.0
        self.M2 = 0.0

    def update(self, x):
        n_old = len(self.window)
        if n_old == self.window.maxlen:
            old = self.window.popleft()
            delta_old = old - self.mean
            self.mean -= delta_old / self.window.maxlen
            self.M2 -= delta_old * (old - self.mean)
        self.window.append(x)
        n = len(self.window)
        delta = x - self.mean
        self.mean += delta / n
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def std(self):
        return (self.M2 / max(len(self.window), 1))**0.5

# ==== LOAD ALL ACCOUNTS AT STARTUP ====
def preload_accounts(save_dir=SAVE_DIR):
    accounts = []
    for filename in os.listdir(save_dir):
        if filename.startswith("model_") and filename.endswith(".h5"):
            account = filename[len("model_"):-3]
            accounts.append(account)

    for account in accounts:
        try:
            model_path = f"{save_dir}/model_{account}.h5"
            scaler_path = f"{save_dir}/scaler_{account}.pkl"
            last_window_path = f"{save_dir}/last_window_{account}.npy"
            aare_window_path = f"{save_dir}/aare_window_{account}.npy"

            MODEL_CACHE[account] = load_model(model_path)
            SCALER_CACHE[account] = joblib.load(scaler_path)
            last_window = np.load(last_window_path)
            WINDOW_CACHE[account] = last_window

            # init AARE history
            aare_list = list(np.load(aare_window_path))
            AARE_CACHE[account] = {
                "deque": deque(aare_list, maxlen=WINDOW_SIZE),
                "stat": RunningStat(WINDOW_SIZE)
            }
            for a in aare_list:
                AARE_CACHE[account]["stat"].update(a)

            print(f"✅ Loaded account {account}")

        except Exception as e:
            print(f"⚠️ Failed to load account {account}: {e}")

# ==== ANOMALY CHECK FUNCTION - FIXED THRESHOLD ====
def check_new_transaction(account: str, new_amount: float):
    if account not in MODEL_CACHE:
        raise HTTPException(status_code=404, detail="Account model not found")

    model = MODEL_CACHE[account]
    scaler = SCALER_CACHE[account]
    last_window = WINDOW_CACHE[account]
    aare_data = AARE_CACHE[account]

    # log-transform + scale
    x_log = np.log1p(new_amount).astype(float)
    x_scaled = scaler.transform([[x_log]])

    # predict
    X_input = np.expand_dims(last_window, axis=0)
    y_pred_scaled = model.predict(X_input, verbose=0)
    y_pred_log = scaler.inverse_transform(y_pred_scaled.reshape(-1,1)).flatten()[0]

    # compute AARE
    aare_log = float(np.abs(x_log - y_pred_log) / (np.abs(x_log) + EPS))

    # ---- FIXED THRESHOLD ----
    # do NOT update rolling stat / deque
    # threshold = mu + THRESH_SIGMA * sigma
    threshold = np.mean(aare_data["deque"]) + THRESH_SIGMA * np.std(aare_data["deque"])

    # absolute outlier
    train_max_log_approx = scaler.inverse_transform(np.array([[1.0]])).flatten()[0]
    if x_log > train_max_log_approx + 3.0:
        is_anomaly = True
        reason = "absolute_outlier_log"
    else:
        is_anomaly = (aare_log > threshold)
        reason = "aare_threshold"

    # update last_window in memory (optional, tapi ga ngubah threshold)
    last_window = np.vstack([last_window[1:], x_scaled])
    WINDOW_CACHE[account] = last_window

    return {
        "Account": account,
        "Amount": float(new_amount),
        "x_log": float(x_log),
        "y_pred_log": float(y_pred_log),
        "AARE_log": aare_log,
        "Threshold": float(threshold),
        "Is_Anomaly": bool(is_anomaly),
        "Reason": reason
    }

class TransactionRequest(BaseModel):
    account: str
    amount: float

# ==== ENDPOINT ====
@app.post("/check_transaction")
def check_transaction(req: TransactionRequest):
    return check_new_transaction(req.account, req.amount)

@app.post("/check_transaction_batch")
def check_transaction_batch(reqs: List[TransactionRequest]):
    results = []
    for req in reqs:
        res = check_new_transaction(req.account, req.amount)  # fungsi RePAD2/fast function lo
        results.append(res)
    return results

# ==== STARTUP HOOK ====
@app.on_event("startup")
def startup_event():
    print("🚀 Preloading all models...")
    preload_accounts()
    print("✅ All models loaded in memory!")
