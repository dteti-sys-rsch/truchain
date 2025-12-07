import numpy as np
import matplotlib.pyplot as plt
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import MinMaxScaler
import warnings
warnings.filterwarnings('ignore')

print("🔍 RUNNING REPAD DIAGNOSTIC TEST V2 - WITH FIXES...")

def diagnostic_test_v2():
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
    EPOCHS = 30  # Increased epochs
    
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
    
    # === 5. BUILD IMPROVED MODEL ===
    print("\n🧠 5. Building IMPROVED LSTM model...")
    model = Sequential([
        LSTM(32, input_shape=(LOOK_BACK, 1)),  # Increased units
        Dense(16, activation='relu'),          # Added hidden layer
        Dense(1)
    ])
    
    # CHANGED: MSE loss + higher learning rate
    optimizer = Adam(learning_rate=0.01)  # Increased learning rate
    model.compile(loss='mse', optimizer=optimizer, metrics=['mae'])  # MSE loss
    
    print("   Model Architecture:")
    model.summary()
    
    # === 6. TRAIN WITH MONITORING ===
    print("\n🏋️  6. Training model...")
    history = model.fit(
        X_scaled, y_scaled, 
        epochs=EPOCHS, 
        batch_size=16,  # Increased batch size
        verbose=1,
        validation_split=0.2,
        shuffle=True  # Added shuffle
    )
    
    # === 7. EVALUATE PREDICTIONS ===
    print("\n📊 7. Evaluating predictions...")
    predictions_scaled = model.predict(X_scaled, verbose=0)
    predictions_original = scaler.inverse_transform(predictions_scaled)
    
    # Calculate metrics
    mae = np.mean(np.abs(predictions_original - y))
    mse = np.mean((predictions_original - y) ** 2)
    rmse = np.sqrt(mse)
    correlation = np.corrcoef(predictions_original.flatten(), y.flatten())[0, 1]
    
    print(f"   ✅ Final Training Loss (MSE): {history.history['loss'][-1]:.6f}")
    print(f"   ✅ Final Training MAE: {history.history['mae'][-1]:.6f}")
    print(f"   ✅ Prediction MAE: {mae:.2f}")
    print(f"   ✅ Prediction RMSE: {rmse:.2f}") 
    print(f"   ✅ Prediction Correlation: {correlation:.4f}")
    
    # === 8. VISUALIZE RESULTS ===
    print("\n📈 8. Generating visualization...")
    plt.figure(figsize=(15, 10))
    
    # Plot 1: Training loss
    plt.subplot(2, 2, 1)
    plt.plot(history.history['loss'], label='Training Loss (MSE)', linewidth=2)
    if 'val_loss' in history.history:
        plt.plot(history.history['val_loss'], label='Validation Loss (MSE)', linewidth=2)
    plt.title('Model Training Loss (MSE)')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    plt.grid(True)
    plt.yscale('log')  # Log scale untuk lihat improvement jelas
    
    # Plot 2: Training MAE
    plt.subplot(2, 2, 2)
    plt.plot(history.history['mae'], label='Training MAE', linewidth=2)
    if 'val_mae' in history.history:
        plt.plot(history.history['val_mae'], label='Validation MAE', linewidth=2)
    plt.title('Model Training MAE')
    plt.xlabel('Epoch')
    plt.ylabel('MAE')
    plt.legend()
    plt.grid(True)
    
    # Plot 3: Predictions vs Actual (first 50 points)
    plt.subplot(2, 2, 3)
    plt.plot(y[:50], label='Actual', marker='o', alpha=0.7, linewidth=2)
    plt.plot(predictions_original[:50], label='Predicted', marker='x', alpha=0.7, linewidth=2)
    plt.title('Predictions vs Actual (First 50 points)')
    plt.xlabel('Time Step')
    plt.ylabel('Value')
    plt.legend()
    plt.grid(True)
    
    # Plot 4: Error distribution
    plt.subplot(2, 2, 4)
    errors = predictions_original.flatten() - y
    plt.hist(errors, bins=30, alpha=0.7, color='red')
    plt.axvline(0, color='black', linestyle='--', linewidth=2)
    plt.title('Prediction Error Distribution')
    plt.xlabel('Error')
    plt.ylabel('Frequency')
    plt.grid(True)
    
    plt.tight_layout()
    plt.show()
    
    # === 9. DIAGNOSTIC CONCLUSION ===
    print("\n🎯 9. DIAGNOSTIC RESULTS V2:")
    
    # Updated thresholds for MSE
    if history.history['loss'][-1] < 0.001:
        print("   ✅ LOSS (MSE): PASS - Excellent learning")
    elif history.history['loss'][-1] < 0.01:
        print("   ✅ LOSS (MSE): PASS - Good learning")
    elif history.history['loss'][-1] < 0.05:
        print("   ⚠️  LOSS (MSE): WARNING - Moderate learning")
    else:
        print("   ❌ LOSS (MSE): FAIL - Poor learning")
    
    if mae < 5.0:
        print("   ✅ MAE: PASS - Excellent prediction accuracy")
    elif mae < 10.0:
        print("   ✅ MAE: PASS - Good prediction accuracy")
    elif mae < 15.0:
        print("   ⚠️  MAE: WARNING - Moderate prediction accuracy")
    else:
        print("   ❌ MAE: FAIL - Poor prediction accuracy")
    
    if correlation > 0.9:
        print("   ✅ CORRELATION: PASS - Excellent pattern recognition")
    elif correlation > 0.7:
        print("   ✅ CORRELATION: PASS - Good pattern recognition")
    elif correlation > 0.5:
        print("   ⚠️  CORRELATION: WARNING - Moderate pattern recognition") 
    else:
        print("   ❌ CORRELATION: FAIL - Weak pattern recognition")
    
    # Check if loss decreased during training
    loss_decrease = history.history['loss'][0] - history.history['loss'][-1]
    if loss_decrease > 0.1:
        print("   ✅ TRAINING: PASS - Loss decreased significantly")
    elif loss_decrease > 0.01:
        print("   ⚠️  TRAINING: WARNING - Loss decreased moderately")
    else:
        print("   ❌ TRAINING: FAIL - Loss didn't decrease properly")
    
    return {
        'final_loss': history.history['loss'][-1],
        'final_mae': history.history['mae'][-1],
        'prediction_mae': mae,
        'prediction_rmse': rmse,
        'correlation': correlation,
        'loss_decrease': loss_decrease
    }

# === RUN THE DIAGNOSTIC ===
if __name__ == "__main__":
    try:
        print("🚀 Starting Diagnostic Test V2 with improvements...")
        print("   Changes: MSE loss, higher learning rate, more layers")
        print("=" * 60)
        
        results = diagnostic_test_v2()
        
        print(f"\n{'='*60}")
        print("🎯 DIAGNOSTIC V2 SUMMARY:")
        print(f"   Final Loss (MSE): {results['final_loss']:.6f}")
        print(f"   Final MAE: {results['final_mae']:.6f}")
        print(f"   Prediction MAE: {results['prediction_mae']:.2f}")
        print(f"   Prediction RMSE: {results['prediction_rmse']:.2f}")
        print(f"   Correlation: {results['correlation']:.4f}")
        print(f"   Loss Decrease: {results['loss_decrease']:.4f}")
        
        # Overall assessment
        if (results['final_loss'] < 0.01 and 
            results['prediction_mae'] < 10.0 and 
            results['correlation'] > 0.8):
            print("💪 OVERALL: EXCELLENT - System is working properly!")
        elif (results['final_loss'] < 0.05 and 
              results['prediction_mae'] < 15.0 and 
              results['correlation'] > 0.6):
            print("👍 OVERALL: GOOD - System is working adequately")
        else:
            print("😞 OVERALL: POOR - System needs more tuning")
            
        print(f"{'='*60}")
        
    except Exception as e:
        print(f"❌ DIAGNOSTIC FAILED WITH ERROR: {e}")
        import traceback
        traceback.print_exc()
