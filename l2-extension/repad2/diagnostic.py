import numpy as np
import matplotlib.pyplot as plt
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
from sklearn.preprocessing import MinMaxScaler

print("🔍 RUNNING REPAD DIAGNOSTIC TEST...")

def diagnostic_test():
    # === 1. CREATE SYNTHETIC DATA WITH CLEAR PATTERN ===
    print("\n📊 1. Creating synthetic data with clear pattern...")
    np.random.seed(42)
    t = np.arange(200)
    # Very obvious pattern: sine wave + trend
    synthetic_data = 100 + 20 * np.sin(t/10) + 5 * np.sin(t/3) + 0.1 * t
    # Add small noise
    synthetic_data += np.random.normal(0, 2, len(t))
    
    print(f"   Data shape: {synthetic_data.shape}")
    print(f"   Data range: {synthetic_data.min():.1f} to {synthetic_data.max():.1f}")
    
    # === 2. SETUP PARAMETERS ===
    LOOK_BACK = 5
    EPOCHS = 20
    
    print(f"\n⚙️  2. Parameters: LOOK_BACK={LOOK_BACK}, EPOCHS={EPOCHS}")
    
    # === 3. PREPARE TRAINING DATA ===
    print("\n📈 3. Preparing training data...")
    X, y = [], []
    for i in range(len(synthetic_data) - LOOK_BACK):
        X.append(synthetic_data[i:i + LOOK_BACK])
        y.append(synthetic_data[i + LOOK_BACK])
    
    X, y = np.array(X), np.array(y)
    print(f"   X shape: {X.shape}, y shape: {y.shape}")
    
    # === 4. SCALE DATA ===
    print("\n🔢 4. Scaling data...")
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X.reshape(-1, 1)).reshape(-1, LOOK_BACK, 1)
    y_scaled = scaler.transform(y.reshape(-1, 1))
    
    print(f"   X_scaled range: {X_scaled.min():.3f} to {X_scaled.max():.3f}")
    print(f"   y_scaled range: {y_scaled.min():.3f} to {y_scaled.max():.3f}")
    
    # === 5. BUILD MODEL ===
    print("\n🧠 5. Building LSTM model...")
    model = Sequential([
        LSTM(16, input_shape=(LOOK_BACK, 1)),
        Dense(1)
    ])
    model.compile(loss='mae', optimizer='adam', metrics=['mae'])
    model.summary()
    
    # === 6. TRAIN WITH MONITORING ===
    print("\n🏋️  6. Training model...")
    history = model.fit(
        X_scaled, y_scaled, 
        epochs=EPOCHS, 
        batch_size=8,
        verbose=1,  # SHOW PROGRESS!
        validation_split=0.2
    )
    
    # === 7. EVALUATE PREDICTIONS ===
    print("\n📊 7. Evaluating predictions...")
    predictions_scaled = model.predict(X_scaled, verbose=0)
    predictions_original = scaler.inverse_transform(predictions_scaled)
    
    # Calculate metrics
    mae = np.mean(np.abs(predictions_original - y))
    mse = np.mean((predictions_original - y) ** 2)
    correlation = np.corrcoef(predictions_original.flatten(), y.flatten())[0, 1]
    
    print(f"   ✅ Final Training Loss: {history.history['loss'][-1]:.4f}")
    print(f"   ✅ Prediction MAE: {mae:.2f}")
    print(f"   ✅ Prediction MSE: {mse:.2f}") 
    print(f"   ✅ Prediction Correlation: {correlation:.4f}")
    
    # === 8. VISUALIZE RESULTS ===
    print("\n📈 8. Generating visualization...")
    plt.figure(figsize=(15, 10))
    
    # Plot 1: Training loss
    plt.subplot(2, 2, 1)
    plt.plot(history.history['loss'], label='Training Loss')
    if 'val_loss' in history.history:
        plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.title('Model Training Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    plt.grid(True)
    
    # Plot 2: Predictions vs Actual (first 50 points)
    plt.subplot(2, 2, 2)
    plt.plot(y[:50], label='Actual', marker='o', alpha=0.7)
    plt.plot(predictions_original[:50], label='Predicted', marker='x', alpha=0.7)
    plt.title('Predictions vs Actual (First 50 points)')
    plt.xlabel('Time Step')
    plt.ylabel('Value')
    plt.legend()
    plt.grid(True)
    
    # Plot 3: Full sequence
    plt.subplot(2, 2, 3)
    plt.plot(y, label='Actual', alpha=0.7)
    plt.plot(predictions_original, label='Predicted', alpha=0.7)
    plt.title('Full Sequence: Predictions vs Actual')
    plt.xlabel('Time Step')
    plt.ylabel('Value')
    plt.legend()
    plt.grid(True)
    
    # Plot 4: Error distribution
    plt.subplot(2, 2, 4)
    errors = predictions_original.flatten() - y
    plt.hist(errors, bins=30, alpha=0.7)
    plt.title('Prediction Error Distribution')
    plt.xlabel('Error')
    plt.ylabel('Frequency')
    plt.grid(True)
    
    plt.tight_layout()
    plt.show()
    
    # === 9. DIAGNOSTIC CONCLUSION ===
    print("\n🎯 9. DIAGNOSTIC RESULTS:")
    
    if history.history['loss'][-1] < 0.05:
        print("   ✅ LOSS: PASS - Model is learning properly")
    else:
        print("   ❌ LOSS: FAIL - Model not learning (loss too high)")
    
    if mae < 10.0:
        print("   ✅ MAE: PASS - Good prediction accuracy")
    else:
        print("   ❌ MAE: FAIL - Poor prediction accuracy")
    
    if correlation > 0.8:
        print("   ✅ CORRELATION: PASS - Strong pattern recognition")
    elif correlation > 0.5:
        print("   ⚠️ CORRELATION: WARNING - Moderate pattern recognition") 
    else:
        print("   ❌ CORRELATION: FAIL - Weak pattern recognition")
    
    # Check if loss decreased during training
    loss_decrease = history.history['loss'][0] - history.history['loss'][-1]
    if loss_decrease > 0.02:
        print("   ✅ TRAINING: PASS - Loss decreased significantly")
    else:
        print("   ❌ TRAINING: FAIL - Loss didn't decrease properly")
    
    return {
        'final_loss': history.history['loss'][-1],
        'mae': mae,
        'correlation': correlation,
        'loss_decrease': loss_decrease
    }

# === RUN THE DIAGNOSTIC ===
if __name__ == "__main__":
    try:
        results = diagnostic_test()
        
        print(f"\n{'='*50}")
        print("🎯 DIAGNOSTIC SUMMARY:")
        print(f"   Final Loss: {results['final_loss']:.4f}")
        print(f"   MAE: {results['mae']:.2f}")
        print(f"   Correlation: {results['correlation']:.4f}")
        print(f"   Loss Decrease: {results['loss_decrease']:.4f}")
        print(f"{'='*50}")
        
    except Exception as e:
        print(f"❌ DIAGNOSTIC FAILED WITH ERROR: {e}")
        import traceback
        traceback.print_exc()
