import numpy as np
import pandas as pd
import joblib, os
from tensorflow.keras.models import load_model
from sklearn.metrics import silhouette_score, f1_score
from datetime import timedelta

# ==== CONFIG ====
SAVE_DIR = "experiment/repad2_models"
DATA_PATH = "filtered_100_700.csv"
WINDOW_SIZE = 1000
THRESH_SIGMA = 1.5
EPS = 1e-8

# ==== LOAD DATA ====
df = pd.read_csv(DATA_PATH, parse_dates=["Timestamp"])
df = df.sort_values(["Account", "Timestamp"])
print(f"📂 Loaded {len(df):,} rows across {df['Account'].nunique()} accounts\n")


# ==== 1. CHECK FUNCTION ====
def check_new_transaction_fixed(account, new_amount):
    model_path = f"{SAVE_DIR}/model_{account}.h5"
    window_path = f"{SAVE_DIR}/aare_window_{account}.npy"
    last_window_path = f"{SAVE_DIR}/last_window_{account}.npy"
    scaler_path = f"{SAVE_DIR}/scaler_{account}.pkl"

    if not os.path.exists(model_path):
        return None

    model = load_model(model_path)
    AAREs = list(np.load(window_path))
    last_window = np.load(last_window_path)
    scaler = joblib.load(scaler_path)

    # Transform
    x_log = np.log1p(new_amount)
    x_scaled = scaler.transform([[x_log]])
    X_input = np.expand_dims(last_window, axis=0)
    y_pred_scaled = model.predict(X_input, verbose=0)
    y_pred_log = scaler.inverse_transform(y_pred_scaled.reshape(-1, 1)).flatten()[0]

    # Compute AARE
    aare_log = float(np.abs(x_log - y_pred_log) / (np.abs(x_log) + EPS))
    AAREs.append(aare_log)

    # Threshold
    recent = AAREs[-min(len(AAREs), WINDOW_SIZE):]
    mu, sigma = np.mean(recent), np.std(recent)
    threshold = mu + THRESH_SIGMA * sigma

    # Check anomaly
    train_max_log_approx = scaler.inverse_transform(np.array([[1.0]])).flatten()[0]
    if x_log > train_max_log_approx + 3.0:
        is_anomaly = True
        reason = "absolute_outlier_log"
    else:
        is_anomaly = (aare_log > threshold)
        reason = "aare_threshold"

    return {
        "AARE_log": aare_log,
        "Threshold": threshold,
        "Is_Anomaly": is_anomaly,
        "Reason": reason
    }


# ==== 2. METRICS ====
def unsupervised_metrics(aare_array, flags_binary):
    if len(aare_array) == 0:
        return {"mean_aare": np.nan, "std_aare": np.nan, "anomaly_ratio": np.nan, "silhouette": np.nan, "pseudo_f1": np.nan}
    mean_aare = np.nanmean(aare_array)
    std_aare = np.nanstd(aare_array)
    anomaly_ratio = np.mean(flags_binary)
    sil = silhouette_score(aare_array.reshape(-1, 1), flags_binary) if len(np.unique(flags_binary)) > 1 else np.nan
    cutoff = np.percentile(aare_array, 95)
    pseudo_true = (aare_array >= cutoff).astype(int)
    pseudo_f1 = f1_score(pseudo_true, flags_binary, zero_division=0)
    return {
        "mean_aare": mean_aare,
        "std_aare": std_aare,
        "anomaly_ratio": anomaly_ratio,
        "silhouette": sil,
        "pseudo_f1": pseudo_f1
    }


# ==== 3. TEST SCENARIOS ====
def simulate_outlier_tests(account):
    print(f"\n🧪 Testing account: {account}")
    model_path = f"{SAVE_DIR}/model_{account}.h5"
    if not os.path.exists(model_path):
        print("⚠️ Model not found, skipping.")
        return None

    # Load original account data
    acc_df = df[df["Account"] == account].sort_values("Timestamp")
    base_amounts = acc_df["Amount Received"].astype(float).values
    if len(base_amounts) < 10:
        print("⚠️ Not enough transactions for test.")
        return None

    # === CASE 1: Normal continuation ===
    test_normal = [np.random.choice(base_amounts) for _ in range(20)]
    # === CASE 2: Outlier injection ===
    test_outlier = [np.max(base_amounts) * 1000]
    # === CASE 3: Smurfing simulation (many small tx summing big) ===
    total_target = np.max(base_amounts) * 50
    smurf_parts = np.random.dirichlet(np.ones(50)) * total_target
    test_smurf = smurf_parts.tolist()

    # Run all
    cases = {"Normal": test_normal, "Outlier": test_outlier, "Smurfing": test_smurf}
    results = {}

    for cname, arr in cases.items():
        aare_list, flag_list = [], []
        for amt in arr:
            res = check_new_transaction_fixed(account, amt)
            if res:
                aare_list.append(res["AARE_log"])
                flag_list.append(int(res["Is_Anomaly"]))
        if len(aare_list) > 0:
            results[cname] = unsupervised_metrics(np.array(aare_list), np.array(flag_list))

    # Print
    for cname, m in results.items():
        print(f"\n📊 {cname} scenario:")
        for k, v in m.items():
            print(f"  - {k:<15}: {v:.4f}" if not np.isnan(v) else f"  - {k:<15}: NaN")

    return results


# ==== 4. MAIN EVALUATION ====
accounts = df["Account"].unique()
np.random.seed(42)
sample_accounts = np.random.choice(accounts, size=min(5, len(accounts)), replace=False)

all_results = {}
for acc in sample_accounts:
    r = simulate_outlier_tests(acc)
    if r:
        all_results[acc] = r

print("\n✅ Evaluation complete.")
