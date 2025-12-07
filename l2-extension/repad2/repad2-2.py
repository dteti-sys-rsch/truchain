import pandas as pd
import numpy as np
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import RobustScaler
import joblib, os

# ==== IMPROVED PARAMETERS ====
LOOK_BACK = 100
WINDOW_SIZE = 1000
THRESH_SIGMA = 0.3
EPOCHS = 50
SAVE_DIR = "experiment/repad2_models_improved"
os.makedirs(SAVE_DIR, exist_ok=True)

# ==== 1. LOAD & FILTER DATA ====
df = pd.read_csv("filtered_100_700.csv", parse_dates=["Timestamp"])
df = df.sort_values(["Account", "Timestamp"])

# Filter akun aktif
tx_count = df.groupby("Account").size().reset_index(name="Transaction Count")
valid_accounts = tx_count[tx_count["Transaction Count"] >= LOOK_BACK * 2]["Account"]  # More strict
df = df[df["Account"].isin(valid_accounts)]

print(f"✅ Total akun aktif: {len(valid_accounts)}")
print(f"✅ Total baris data: {len(df)}")
print(f"⚙️  Parameters: LOOK_BACK={LOOK_BACK}, EPOCHS={EPOCHS}")

# ==== 2. IMPROVED TRAINING PER ACCOUNT ====
def train_repad2_improved(acc, group):
    data = group["Amount Received"].values.astype(float)
    if len(data) < LOOK_BACK * 2:
        print(f"⚠️  Account {acc}: Insufficient data ({len(data)} < {LOOK_BACK*2})")
        return None

    # === IMPROVEMENT 1: RobustScaler instead of MinMax ===
    data = np.log1p(data)
    scaler = RobustScaler()  # More robust to outliers
    data_scaled = scaler.fit_transform(data.reshape(-1, 1))

    # Save scaler
    joblib.dump(scaler, f"{SAVE_DIR}/scaler_{acc}.pkl")

    # Prepare samples
    X, y = [], []
    for i in range(len(data_scaled) - LOOK_BACK):
        X.append(data_scaled[i:i+LOOK_BACK])
        y.append(data_scaled[i+LOOK_BACK])
    X, y = np.array(X), np.array(y)

    # === IMPROVEMENT 2: Better Model Architecture ===
    model = Sequential([
        LSTM(32, input_shape=(LOOK_BACK, 1)),  # Increased units
        Dropout(0.2),                          # Added dropout
        Dense(16, activation='relu'),          # Added hidden layer
        Dropout(0.2),
        Dense(1)
    ])
    
    # === IMPROVEMENT 3: MSE Loss + Adjusted Learning Rate ===
    optimizer = Adam(learning_rate=0.005)
    model.compile(loss='mse', optimizer=optimizer, metrics=['mae'])  # MSE for better convergence
    
    print(f"   🧠 Training {acc} with {len(X)} samples...")
    model.fit(X, y, epochs=EPOCHS, verbose=0, batch_size=16)

    # === IMPROVEMENT 4: Bias Correction Setup ===
    # Calculate initial bias for calibration
    predictions = model.predict(X, verbose=0)
    predictions_original = scaler.inverse_transform(predictions)
    actual_original = scaler.inverse_transform(y.reshape(-1, 1))
    initial_bias = np.mean(predictions_original - actual_original.flatten())
    
    # Online phase with improvements
    AAREs = []
    anomalies = []
    recent_errors = []

    for t in range(LOOK_BACK, len(data_scaled)):
        X_input = np.array([data_scaled[t-LOOK_BACK:t]])
        y_true = data_scaled[t]
        y_pred = model.predict(X_input, verbose=0)

        # === IMPROVEMENT 5: Better Error Calculation ===
        y_true_log = scaler.inverse_transform(y_true.reshape(-1, 1))[0][0]
        y_pred_log = scaler.inverse_transform(y_pred.reshape(-1, 1))[0][0]
        
        # Apply bias correction
        y_pred_log_calibrated = y_pred_log - initial_bias * 0.5  # Partial correction
        
        error = np.abs(y_true_log - y_pred_log_calibrated) / (np.abs(y_true_log) + 1e-6)
        AAREs.append(error)
        recent_errors.append(error)

        # === IMPROVEMENT 6: Dynamic Threshold with Minimum ===
        if len(AAREs) >= LOOK_BACK:
            window = AAREs[-min(len(AAREs), WINDOW_SIZE):]
            mu, sigma = np.mean(window), np.std(window)
            
            # Ensure minimum threshold to prevent too sensitive detection
            min_threshold = 0.02  # Minimum 2% error threshold
            threshold = max(min_threshold, mu + THRESH_SIGMA * sigma)
            
            if AAREs[-1] > threshold:
                anomalies.append({
                    "Account": acc,
                    "Index": t,
                    "AARE": AAREs[-1],
                    "Threshold": threshold,
                    "Actual_Amount": np.expm1(y_true_log),  # Original amount
                    "Predicted_Amount": np.expm1(y_pred_log_calibrated)
                })

        # === IMPROVEMENT 7: Smart Retraining (Disabled for now) ===
        # if t % 100 == 0 and t > 200 and len(recent_errors) > 50:
        #     recent_performance = np.mean(recent_errors[-50:])
        #     if recent_performance > threshold * 1.5:  # Retrain if performance drops
        #         model.fit(X[t-50:t], y[t-50:t], epochs=3, verbose=0, batch_size=8)
        #         recent_errors = []  # Reset error tracking
    
    # Save states with metadata
    np.save(f"{SAVE_DIR}/aare_window_{acc}.npy", np.array(AAREs[-WINDOW_SIZE:]))
    np.save(f"{SAVE_DIR}/last_window_{acc}.npy", data_scaled[-LOOK_BACK:])
    np.save(f"{SAVE_DIR}/train_max_log_{acc}.npy", data.max())
    np.save(f"{SAVE_DIR}/initial_bias_{acc}.npy", initial_bias)  # Save bias for inference
    
    model.save(f"{SAVE_DIR}/model_{acc}.h5")
    
    # Print training summary
    avg_aare = np.mean(AAREs) if AAREs else 0
    print(f"   ✅ {acc}: {len(anomalies)} anomalies, Avg AARE: {avg_aare:.4f}")
    
    return anomalies

# ==== 3. TRAIN ALL ACCOUNTS ====
print(f"\n🚀 Starting improved training for {len(valid_accounts)} accounts...")
all_anomalies = []
successful_accounts = 0

for acc, group in df.groupby("Account"):
    try:
        anomalies = train_repad2_improved(acc, group)
        if anomalies:
            all_anomalies.extend(anomalies)
            successful_accounts += 1
    except Exception as e:
        print(f"❌ Error training {acc}: {e}")

# Save results with improved formatting
if all_anomalies:
    results_df = pd.DataFrame(all_anomalies)
    results_df.to_csv("detected_anomalies_improved.csv", index=False)
    print(f"\n✅ Saved {len(results_df)} anomalies from {successful_accounts} accounts")
    
    # Print summary statistics
    print(f"\n📊 ANOMALY DETECTION SUMMARY:")
    print(f"   Total anomalies detected: {len(results_df)}")
    print(f"   Accounts with anomalies: {successful_accounts}")
    print(f"   Average AARE: {results_df['AARE'].mean():.4f}")
    print(f"   Average Threshold: {results_df['Threshold'].mean():.4f}")
else:
    print("❌ No anomalies detected")

print(f"\n🎯 IMPROVED TRAINING COMPLETE!")
print(f"   Models saved to: {SAVE_DIR}")
print(f"   Anomalies saved to: detected_anomalies_improved.csv")
