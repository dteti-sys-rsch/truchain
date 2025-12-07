import numpy as np
import pandas as pd
import joblib, os
from tensorflow.keras.models import load_model
from sklearn.metrics import silhouette_score, f1_score
from datetime import timedelta

# ==== CONFIG - MATCH WITH TRAINING ====
SAVE_DIR = "experiment/repad2_models_improved"  # Updated directory
DATA_PATH = "filtered_100_700.csv"
WINDOW_SIZE = 1000
THRESH_SIGMA = 0.3
EPS = 1e-8
MIN_THRESHOLD = 0.02  # Minimum threshold to prevent oversensitivity

# ==== LOAD DATA ====
df = pd.read_csv(DATA_PATH, parse_dates=["Timestamp"])
df = df.sort_values(["Account", "Timestamp"])
print(f"📂 Loaded {len(df):,} rows across {df['Account'].nunique()} accounts\n")

# ==== 1. IMPROVED CHECK FUNCTION ====
def check_new_transaction_improved(account, new_amount):
    model_path = f"{SAVE_DIR}/model_{account}.h5"
    window_path = f"{SAVE_DIR}/aare_window_{account}.npy"
    last_window_path = f"{SAVE_DIR}/last_window_{account}.npy"
    scaler_path = f"{SAVE_DIR}/scaler_{account}.pkl"
    bias_path = f"{SAVE_DIR}/initial_bias_{account}.npy"

    if not os.path.exists(model_path):
        return None

    try:
        model = load_model(model_path)
        AAREs = list(np.load(window_path))
        last_window = np.load(last_window_path)
        scaler = joblib.load(scaler_path)
        
        # Load bias for calibration if exists
        if os.path.exists(bias_path):
            initial_bias = np.load(bias_path)
        else:
            initial_bias = 0.0

        # Transform
        x_log = np.log1p(new_amount)
        x_scaled = scaler.transform([[x_log]])
        X_input = np.expand_dims(last_window, axis=0)
        y_pred_scaled = model.predict(X_input, verbose=0)
        y_pred_log = scaler.inverse_transform(y_pred_scaled.reshape(-1, 1)).flatten()[0]
        
        # === IMPROVEMENT: Apply bias correction ===
        y_pred_log_calibrated = y_pred_log - initial_bias * 0.5

        # Compute AARE with calibrated prediction
        aare_log = float(np.abs(x_log - y_pred_log_calibrated) / (np.abs(x_log) + EPS))
        AAREs.append(aare_log)

        # === IMPROVEMENT: Dynamic threshold with minimum ===
        recent = AAREs[-min(len(AAREs), WINDOW_SIZE):]
        mu, sigma = np.mean(recent), np.std(recent)
        threshold = max(MIN_THRESHOLD, mu + THRESH_SIGMA * sigma)  # Ensure minimum threshold

        # Check anomaly with improved logic
        train_max_log_approx = scaler.inverse_transform(np.array([[1.0]])).flatten()[0]
        if x_log > train_max_log_approx + 3.0:
            is_anomaly = True
            reason = "absolute_outlier_log"
        elif aare_log > threshold * 1.5:  # Higher confidence for strong anomalies
            is_anomaly = True
            reason = "strong_aare_threshold"
        elif aare_log > threshold:
            is_anomaly = True
            reason = "aare_threshold"
        else:
            is_anomaly = False
            reason = "normal"

        return {
            "AARE_log": aare_log,
            "Threshold": threshold,
            "Is_Anomaly": is_anomaly,
            "Reason": reason,
            "Predicted_Amount": np.expm1(y_pred_log_calibrated),
            "Actual_Amount": new_amount,
            "Bias_Correction": initial_bias * 0.5
        }
    
    except Exception as e:
        print(f"❌ Error processing account {account}: {e}")
        return None

# ==== 2. ENHANCED METRICS ====
def enhanced_unsupervised_metrics(aare_array, flags_binary, actual_amounts=None, predicted_amounts=None):
    if len(aare_array) == 0:
        return {
            "mean_aare": np.nan, "std_aare": np.nan, 
            "anomaly_ratio": np.nan, "silhouette": np.nan, 
            "pseudo_f1": np.nan, "mape": np.nan, "bias": np.nan
        }
    
    mean_aare = np.nanmean(aare_array)
    std_aare = np.nanstd(aare_array)
    anomaly_ratio = np.mean(flags_binary)
    
    # Silhouette score
    sil = silhouette_score(aare_array.reshape(-1, 1), flags_binary) if len(np.unique(flags_binary)) > 1 else np.nan
    
    # Pseudo F1 score
    cutoff = np.percentile(aare_array, 95)
    pseudo_true = (aare_array >= cutoff).astype(int)
    pseudo_f1 = f1_score(pseudo_true, flags_binary, zero_division=0)
    
    # Additional financial metrics
    mape = np.nan
    bias = np.nan
    if actual_amounts is not None and predicted_amounts is not None:
        valid_mask = (actual_amounts > 0) & (predicted_amounts > 0)
        if np.any(valid_mask):
            actual_valid = actual_amounts[valid_mask]
            predicted_valid = predicted_amounts[valid_mask]
            mape = np.mean(np.abs(actual_valid - predicted_valid) / actual_valid) * 100
            bias = np.mean(predicted_valid - actual_valid)
    
    return {
        "mean_aare": mean_aare,
        "std_aare": std_aare,
        "anomaly_ratio": anomaly_ratio,
        "silhouette": sil,
        "pseudo_f1": pseudo_f1,
        "mape": mape,
        "bias": bias,
        "total_tests": len(aare_array),
        "anomalies_detected": np.sum(flags_binary)
    }

# ==== 3. ENHANCED TEST SCENARIOS ====
def simulate_enhanced_outlier_tests(account):
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

    # === IMPROVED TEST CASES ===
    median_amount = np.median(base_amounts)
    std_amount = np.std(base_amounts)
    
    # CASE 1: Normal continuation (more realistic)
    test_normal = [np.random.normal(median_amount, std_amount/2) for _ in range(20)]
    test_normal = [max(1, x) for x in test_normal]  # Ensure positive
    
    # CASE 2: Realistic outlier injection
    test_outlier = [median_amount * 100]  # More realistic outlier
    
    # CASE 3: Smurfing simulation (improved)
    total_target = median_amount * 30  # More realistic total
    smurf_parts = np.random.dirichlet(np.ones(30)) * total_target
    test_smurf = [max(1, x) for x in smurf_parts.tolist()]
    
    # CASE 4: Gradual anomaly (slow drift)
    test_gradual = [median_amount * (1 + 0.1 * i) for i in range(10)]  # 10% increase each step

    cases = {
        "Normal": test_normal, 
        "Outlier": test_outlier, 
        "Smurfing": test_smurf,
        "Gradual": test_gradual
    }
    
    results = {}

    for cname, amounts in cases.items():
        aare_list, flag_list, actual_list, pred_list = [], [], [], []
        for amt in amounts:
            res = check_new_transaction_improved(account, amt)
            if res:
                aare_list.append(res["AARE_log"])
                flag_list.append(int(res["Is_Anomaly"]))
                actual_list.append(res["Actual_Amount"])
                pred_list.append(res["Predicted_Amount"])
        
        if len(aare_list) > 0:
            results[cname] = enhanced_unsupervised_metrics(
                np.array(aare_list), 
                np.array(flag_list),
                np.array(actual_list),
                np.array(pred_list)
            )

    # Enhanced printing
    for cname, m in results.items():
        print(f"\n📊 {cname} scenario ({m['total_tests']} tests):")
        print(f"  - Anomalies: {m['anomalies_detected']}/{m['total_tests']} ({m['anomaly_ratio']:.1%})")
        print(f"  - Mean AARE: {m['mean_aare']:.4f}")
        if not np.isnan(m['mape']):
            print(f"  - MAPE: {m['mape']:.2f}%")
        if not np.isnan(m['bias']):
            print(f"  - Bias: {m['bias']:.2f}")
        print(f"  - Pseudo F1: {m['pseudo_f1']:.4f}")

    return results

# ==== 4. COMPREHENSIVE EVALUATION ====
def comprehensive_evaluation():
    accounts = df["Account"].unique()
    np.random.seed(42)
    sample_accounts = np.random.choice(accounts, size=min(8, len(accounts)), replace=False)
    
    print(f"🔍 Running comprehensive evaluation on {len(sample_accounts)} accounts...")
    print(f"📁 Model directory: {SAVE_DIR}")
    print("=" * 60)

    all_results = {}
    successful_tests = 0
    
    for i, acc in enumerate(sample_accounts, 1):
        print(f"\n[{i}/{len(sample_accounts)}] ", end="")
        r = simulate_enhanced_outlier_tests(acc)
        if r:
            all_results[acc] = r
            successful_tests += 1

    # Summary statistics
    print(f"\n{'='*60}")
    print("🎯 COMPREHENSIVE EVALUATION SUMMARY")
    print(f"{'='*60}")
    print(f"📊 Accounts tested: {successful_tests}/{len(sample_accounts)}")
    
    if successful_tests > 0:
        # Aggregate metrics across all accounts and scenarios
        all_metrics = []
        for acc, scenarios in all_results.items():
            for scenario, metrics in scenarios.items():
                metrics['account'] = acc
                metrics['scenario'] = scenario
                all_metrics.append(metrics)
        
        metrics_df = pd.DataFrame(all_metrics)
        
        print(f"\n📈 OVERALL PERFORMANCE:")
        print(f"  - Average Anomaly Detection Rate: {metrics_df['anomaly_ratio'].mean():.1%}")
        print(f"  - Average AARE: {metrics_df['mean_aare'].mean():.4f}")
        print(f"  - Average Pseudo F1: {metrics_df['pseudo_f1'].mean():.4f}")
        
        # Scenario-wise performance
        print(f"\n🎯 SCENARIO PERFORMANCE:")
        for scenario in ['Normal', 'Outlier', 'Smurfing', 'Gradual']:
            scenario_data = metrics_df[metrics_df['scenario'] == scenario]
            if len(scenario_data) > 0:
                anomaly_rate = scenario_data['anomaly_ratio'].mean()
                print(f"  - {scenario:<10}: {anomaly_rate:.1%} anomaly rate")
        
        print(f"\n💡 INTERPRETATION:")
        print("  ✅ Ideal: High anomaly rate for Outlier, low for Normal")
        print("  ✅ Good MAPE: <10%, Good AARE: <0.05")
        
    print(f"\n✅ Enhanced evaluation complete!")
    return all_results

# ==== RUN ENHANCED EVALUATION ====
if __name__ == "__main__":
    results = comprehensive_evaluation()
