import pandas as pd
import numpy as np
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense
from sklearn.preprocessing import MinMaxScaler
import joblib, os

# ==== PARAMETER ====
LOOK_BACK = 100
WINDOW_SIZE = 1000
THRESH_SIGMA = 0.3
EPOCHS = 50
SAVE_DIR = "experiment/repad2_models"
os.makedirs(SAVE_DIR, exist_ok=True)

# ==== 1. LOAD & FILTER DATA ====
df = pd.read_csv("filtered_100_700.csv", parse_dates=["Timestamp"])
df = df.sort_values(["Account", "Timestamp"])

# Filter akun aktif
tx_count = df.groupby("Account").size().reset_index(name="Transaction Count")
valid_accounts = tx_count[tx_count["Transaction Count"] >= 10]["Account"]
df = df[df["Account"].isin(valid_accounts)]

print(f"✅ Total akun aktif: {len(valid_accounts)}")
print(f"✅ Total baris data: {len(df)}")

# ==== 2. TRAINING PER ACCOUNT ====
def train_repad2_per_account(acc, group):
    data = group["Amount Received"].values.astype(float)
    if len(data) < LOOK_BACK * 2:
        return None

    data = np.log1p(data)
    scaler = MinMaxScaler()
    data_scaled = scaler.fit_transform(data.reshape(-1, 1))

    # Save scaler
    joblib.dump(scaler, f"{SAVE_DIR}/scaler_{acc}.pkl")

    # Prepare samples
    X, y = [], []
    for i in range(len(data_scaled) - LOOK_BACK):
        X.append(data_scaled[i:i+LOOK_BACK])
        y.append(data_scaled[i+LOOK_BACK])
    X, y = np.array(X), np.array(y)

    model = Sequential([
        LSTM(64, input_shape=(LOOK_BACK, 1)),
        Dense(1)
    ])
    model.compile(loss='mae', optimizer='adam')
    model.fit(X, y, epochs=EPOCHS, verbose=0)

    # Online phase
    AAREs = []
    anomalies = []

    for t in range(LOOK_BACK, len(data_scaled)):
        X_input = np.array([data_scaled[t-LOOK_BACK:t]])
        y_true = data_scaled[t]
        y_pred = model.predict(X_input, verbose=0)

        # === FIX 1: compute error di log-space ===
        y_true_log = scaler.inverse_transform(y_true.reshape(-1, 1))[0][0]
        y_pred_log = scaler.inverse_transform(y_pred.reshape(-1, 1))[0][0]
        error = np.abs(y_true_log - y_pred_log) / (np.abs(y_true_log) + 1e-6)
        AAREs.append(error)

        # === FIX 2: adaptive threshold tanpa clip ===
        if len(AAREs) >= LOOK_BACK:
            window = AAREs[-min(len(AAREs), WINDOW_SIZE):]
            mu, sigma = np.mean(window), np.std(window)
            threshold = max(0, mu + THRESH_SIGMA * sigma)
            if AAREs[-1] > threshold:
                anomalies.append({
                    "Account": acc,
                    "Index": t,
                    "AARE": AAREs[-1],
                    "Threshold": threshold
                })

        # === FIX 3: retrain ringan optional ===
       	# if t % 10 == 0 and t > 10:
      	 #     model.fit(X[t-10:t], y[t-10:t], epochs=1, verbose=0)
    
    # Save states
    np.save(f"{SAVE_DIR}/aare_window_{acc}.npy", np.array(AAREs[-WINDOW_SIZE:]))
    np.save(f"{SAVE_DIR}/last_window_{acc}.npy", data_scaled[-LOOK_BACK:])
    np.save(f"{SAVE_DIR}/train_max_log_{acc}.npy", data.max())
    model.save(f"{SAVE_DIR}/model_{acc}.h5")

    return anomalies

# Train all
all_anomalies = []
for acc, group in df.groupby("Account"):
    print(f"Training account {acc} ...")
    anomalies = train_repad2_per_account(acc, group)
    if anomalies:
        all_anomalies.extend(anomalies)

pd.DataFrame(all_anomalies).to_csv("detected_anomalies.csv", index=False)
print("✅ Saved detected_anomalies.csv")
