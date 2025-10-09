import numpy as np
import pandas as pd
import joblib, os
from tensorflow.keras.models import load_model

WINDOW_SIZE = 1000
THRESH_SIGMA = 1.5
SAVE_DIR = "experiment/repad2_models"
EPS = 1e-8

df = pd.read_csv("filtered_100_700.csv", parse_dates=["Timestamp"])
df = df.sort_values(["Account", "Timestamp"])

def check_new_transaction_fixed(account, new_amount):
    model_path = f"{SAVE_DIR}/model_{account}.h5"
    window_path = f"{SAVE_DIR}/aare_window_{account}.npy"
    last_window_path = f"{SAVE_DIR}/last_window_{account}.npy"
    scaler_path = f"{SAVE_DIR}/scaler_{account}.pkl"

    if not os.path.exists(model_path):
        return {"error": "model not found for this account"}

    model = load_model(model_path)
    AAREs = list(np.load(window_path))
    last_window = np.load(last_window_path)           # scaled values (shape LOOK_BACK x 1)
    scaler = joblib.load(scaler_path)                 # scaler fitted on log1p(data)

    # 1) Transform new amount to log-space (same transform used in training)
    x_log = np.log1p(new_amount).astype(float)        # scalar

    # 2) Prepare scaled x for updating last_window (but do NOT use scaled for AARE)
    #    If new log value is outside scaler's training range, scaler.transform will produce >1 or <0.
    x_scaled = scaler.transform([[x_log]])            # shape (1,1)

    # 3) Predict using model (input must be scaled lookback window)
    X_input = np.expand_dims(last_window, axis=0)     # shape (1, LOOK_BACK, 1)
    y_pred_scaled = model.predict(X_input, verbose=0) # shape (1,1)

    # 4) Convert predicted scaled value back to log-space
    y_pred_log = scaler.inverse_transform(y_pred_scaled.reshape(-1, 1)).flatten()[0]

    # 5) Compute AARE in log-space (relative error in log units)
    #    use absolute value denominator to avoid sign issues
    aare_log = float(np.abs(x_log - y_pred_log) / (np.abs(x_log) + EPS))

    # 6) Append to AAREs (we keep AARE history in log-space)
    AAREs.append(aare_log)

    # 7) Compute adaptive threshold (do NOT clip to 1)
    recent = AAREs[-min(len(AAREs), WINDOW_SIZE):]
    mu, sigma = np.mean(recent), np.std(recent)
    threshold = mu + THRESH_SIGMA * sigma

    # 8) Extra absolute rule: if the new log is massively above training range, flag immediately
    #    We can get training max log by inverse-scaling 1.0 (if scaler was MinMax)
    #    But simpler: approximate training max log from last_window:
    train_max_log_approx = scaler.inverse_transform(np.array([[1.0]])).flatten()[0]
    if x_log > train_max_log_approx + 3.0:   # 3 nat units ~ e^3 ≈ 20x bigger. adjust constant as needed
        is_anomaly = True
        reason = "absolute_outlier_log"
    else:
        is_anomaly = (aare_log > threshold)
        reason = "aare_threshold"

    # 9) Update stored state: save AARE window and last_window (use scaled x_scaled)
    # np.save(window_path, np.array(recent))
    # new_lookback = np.vstack([last_window[1:], x_scaled])   # shift in scaled domain
    # np.save(last_window_path, new_lookback)

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

# ==== 4. EXAMPLE ====
example_account = df["Account"].iloc[0]
example_amount = 400000000
result = check_new_transaction_fixed(example_account, example_amount)
print("🔍 Result for new transaction:")
print(result)
