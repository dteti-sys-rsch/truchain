import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import RobustScaler
import warnings
warnings.filterwarnings('ignore')

print("🔍 RUNNING REPAD DIAGNOSTIC TEST V3 - NUMERICAL ONLY...")

def diagnostic_test_v3():
    # === 1. CREATE SYNTHETIC DATA ===
    print("\n📊 1. Creating synthetic data...")
    np.random.seed(42)
    t = np.arange(200)
    synthetic_data = 100 + 20 * np.sin(t/10) + 5 * np.sin(t/3) + 0.1 * t
    synthetic_data += np.random.normal(0, 2, len(t))
    
    # === 2. SETUP PARAMETERS ===
    LOOK_BACK = 5
    EPOCHS = 30
    
    # === 3. PREPARE TRAINING DATA ===
    X, y = [], []
    for i in range(len(synthetic_data) - LOOK_BACK):
        X.append(synthetic_data[i:i + LOOK_BACK])
        y.append(synthetic_data[i + LOOK_BACK])
    
    X, y = np.array(X), np.array(y)
    
    # === 4. SCALE DATA WITH ROBUST SCALER ===
    print("🔢 2. Scaling with RobustScaler...")
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X.reshape(-1, 1)).reshape(-1, LOOK_BACK, 1)
    y_scaled = scaler.transform(y.reshape(-1, 1))
    
    # === 5. BUILD IMPROVED MODEL ===
    print("🧠 3. Building optimized model...")
    model = Sequential([
        LSTM(32, input_shape=(LOOK_BACK, 1)),
        Dropout(0.2),
        Dense(16, activation='relu'),
        Dropout(0.2),
        Dense(8, activation='relu'),
        Dense(1)
    ])
    
    optimizer = Adam(learning_rate=0.005)
    model.compile(loss='mse', optimizer=optimizer, metrics=['mae'])
    
    # === 6. TRAIN MODEL ===
    print("🏋️  4. Training model...")
    history = model.fit(
        X_scaled, y_scaled, 
        epochs=EPOCHS, 
        batch_size=16,
        verbose=0,
        validation_split=0.2
    )
    
    # === 7. EVALUATE PREDICTIONS ===
    print("📊 5. Evaluating predictions...")
    predictions_scaled = model.predict(X_scaled, verbose=0)
    predictions_original = scaler.inverse_transform(predictions_scaled)
    
    # Calculate all metrics
    mae = np.mean(np.abs(predictions_original - y))
    mse = np.mean((predictions_original - y) ** 2)
    rmse = np.sqrt(mse)
    correlation = np.corrcoef(predictions_original.flatten(), y.flatten())[0, 1]
    
    # Additional metrics
    mean_actual = np.mean(y)
    mean_predicted = np.mean(predictions_original)
    mape = np.mean(np.abs((y - predictions_original.flatten()) / y)) * 100
    
    # === 8. PRINT NUMERICAL RESULTS ===
    print("\n🎯 6. NUMERICAL RESULTS:")
    print("=" * 50)
    
    # Training metrics
    print("📈 TRAINING METRICS:")
    print(f"   Final Loss (MSE):     {history.history['loss'][-1]:.6f}")
    print(f"   Final MAE:           {history.history['mae'][-1]:.6f}")
    print(f"   Initial Loss:        {history.history['loss'][0]:.6f}")
    print(f"   Loss Decrease:       {history.history['loss'][0] - history.history['loss'][-1]:.6f}")
    
    # Prediction metrics  
    print("\n📊 PREDICTION METRICS:")
    print(f"   MAE:                 {mae:.2f}")
    print(f"   RMSE:                {rmse:.2f}")
    print(f"   MSE:                 {mse:.2f}")
    print(f"   MAPE:                {mape:.2f}%")
    print(f"   Correlation:         {correlation:.4f}")
    
    # Data statistics
    print("\n📋 DATA STATISTICS:")
    print(f"   Mean Actual:         {mean_actual:.2f}")
    print(f"   Mean Predicted:      {mean_predicted:.2f}")
    print(f"   Bias:                {mean_predicted - mean_actual:.2f}")
    print(f"   Std Actual:          {np.std(y):.2f}")
    print(f"   Std Predicted:       {np.std(predictions_original):.2f}")
    
    # Performance assessment
    print("\n✅ PERFORMANCE ASSESSMENT:")
    
    # MAE Assessment
    if mae < 5.0:
        print(f"   MAE: EXCELLENT (<5)     - {mae:.2f}")
    elif mae < 10.0:
        print(f"   MAE: GOOD (5-10)        - {mae:.2f}")
    elif mae < 15.0:
        print(f"   MAE: MODERATE (10-15)   - {mae:.2f}")
    else:
        print(f"   MAE: POOR (>15)         - {mae:.2f}")
    
    # Correlation Assessment
    if correlation > 0.95:
        print(f"   CORR: EXCELLENT (>0.95) - {correlation:.4f}")
    elif correlation > 0.85:
        print(f"   CORR: VERY GOOD (0.85-0.95) - {correlation:.4f}")
    elif correlation > 0.75:
        print(f"   CORR: GOOD (0.75-0.85) - {correlation:.4f}")
    else:
        print(f"   CORR: MODERATE (<0.75)  - {correlation:.4f}")
    
    # MAPE Assessment
    if mape < 5.0:
        print(f"   MAPE: EXCELLENT (<5%)   - {mape:.2f}%")
    elif mape < 10.0:
        print(f"   MAPE: GOOD (5-10%)      - {mape:.2f}%")
    elif mape < 20.0:
        print(f"   MAPE: MODERATE (10-20%) - {mape:.2f}%")
    else:
        print(f"   MAPE: POOR (>20%)       - {mape:.2f}%")
    
    print("=" * 50)
    
    return {
        'mae': mae,
        'rmse': rmse,
        'mse': mse,
        'mape': mape,
        'correlation': correlation,
        'final_loss': history.history['loss'][-1],
        'bias': mean_predicted - mean_actual
    }

# === RUN THE DIAGNOSTIC ===
if __name__ == "__main__":
    try:
        print("🚀 REPAD Diagnostic V3 - Focus on MAE Improvement")
        print("   Features: RobustScaler, Dropout, Deeper Network")
        results = diagnostic_test_v3()
        
        # Final verdict
        print("\n🎯 FINAL VERDICT:")
        if results['mae'] < 10 and results['correlation'] > 0.85:
            print("💪 EXCELLENT - Ready for real data!")
        elif results['mae'] < 15 and results['correlation'] > 0.75:
            print("👍 GOOD - Minor tuning needed")
        elif results['mae'] < 25 and results['correlation'] > 0.6:
            print("⚠️  MODERATE - Needs optimization")
        else:
            print("❌ POOR - Fundamental issues")
            
    except Exception as e:
        print(f"❌ DIAGNOSTIC FAILED: {e}")
