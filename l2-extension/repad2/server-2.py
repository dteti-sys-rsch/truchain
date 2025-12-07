# server_vectorized.py
import os
import numpy as np
import joblib
from tensorflow.keras.models import load_model
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List

# ==== CONFIG ====
SAVE_DIR = "experiment/repad2_models"
WINDOW_SIZE = 1000
THRESH_SIGMA = 1.5
EPS = 1e-8

app = FastAPI(title="RePAD2 Vectorized Server - CPU Optimized")

# ==== CACHE ====
MODEL_CACHE = {}
SCALER_CACHE = {}
WINDOW_CACHE = {}
AARE_CACHE = {}

# ==== DATA MODELS ====
class TransactionRequest(BaseModel):
    account: str
    amount: float

# ==== INIT / PRELOAD ====
def preload_models():
    accounts = []
    for f in os.listdir(SAVE_DIR):
        if f.startswith("model_") and f.endswith(".h5"):
            acc = f[len("model_"):-3]
            accounts.append(acc)

    for acc in accounts:
        try:
            model_path = f"{SAVE_DIR}/model_{acc}.h5"
            scaler_path = f"{SAVE_DIR}/scaler_{acc}.pkl"
            last_window_path = f"{SAVE_DIR}/last_window_{acc}.npy"
            aare_window_path = f"{SAVE_DIR}/aare_window_{acc}.npy"

            MODEL_CACHE[acc] = load_model(model_path)
            SCALER_CACHE[acc] = joblib.load(scaler_path)
            WINDOW_CACHE[acc] = np.load(last_window_path)
            AARE_CACHE[acc] = np.load(aare_window_path)
            print(f"✅ Loaded model for account {acc}")
        except Exception as e:
            print(f"⚠️ Failed to load {acc}: {e}")

@app.on_event("startup")
def startup_event():
    print("🚀 Preloading all account models...")
    preload_models()
    print("✅ All models loaded into memory.")


# ==== CORE INFERENCE (vectorized per account) ====
def predict_batch(account: str, amounts: List[float]):
    if account not in MODEL_CACHE:
        raise HTTPException(status_code=404, detail=f"Model for account {account} not found")

    model = MODEL_CACHE[account]
    scaler = SCALER_CACHE[account]
    last_window = WINDOW_CACHE[account]
    aare_hist = AARE_CACHE[account]

    # prepare input
    x_log = np.log1p(amounts).reshape(-1, 1)
    x_scaled = scaler.transform(x_log)

    # replicate last window (sama untuk semua tx di batch)
    X_input = np.repeat(np.expand_dims(last_window, axis=0), len(x_scaled), axis=0)

    # single inference untuk seluruh batch
    y_pred_scaled = model.predict(X_input, verbose=0)
    y_pred_log = scaler.inverse_transform(y_pred_scaled.reshape(-1, 1)).flatten()

    # AARE vectorized
    aare_log = np.abs(x_log.flatten() - y_pred_log) / (np.abs(x_log.flatten()) + EPS)

    # fixed threshold
    mu, sigma = np.mean(aare_hist), np.std(aare_hist)
    threshold = mu + THRESH_SIGMA * sigma

    # absolute outlier detection
    train_max_log_approx = scaler.inverse_transform(np.array([[1.0]])).flatten()[0]
    abs_outlier_mask = x_log.flatten() > train_max_log_approx + 3.0
    is_anomaly = np.logical_or(aare_log > threshold, abs_outlier_mask)

    # update last window in cache (optional)
    WINDOW_CACHE[account] = np.vstack([last_window[1:], x_scaled[-1:]])

    # results as list of dicts
    return [
        {
            "Account": account,
            "Amount": float(a),
            "x_log": float(xl),
            "y_pred_log": float(yp),
            "AARE_log": float(aa),
            "Threshold": float(threshold),
            "Is_Anomaly": bool(flag),
            "Reason": "absolute_outlier_log" if absf else "aare_threshold"
        }
        for a, xl, yp, aa, flag, absf in zip(
            amounts, x_log.flatten(), y_pred_log, aare_log, is_anomaly, abs_outlier_mask
        )
    ]


# ==== ENDPOINT ====
@app.post("/check_transaction_batch")
def check_transaction_batch(reqs: List[TransactionRequest]):
    if not reqs:
        raise HTTPException(status_code=400, detail="Empty request batch")

    # group by account biar lebih efisien
    grouped = {}
    for r in reqs:
        grouped.setdefault(r.account, []).append(r.amount)

    results = []
    for acc, amounts in grouped.items():
        results.extend(predict_batch(acc, amounts))

    return results
