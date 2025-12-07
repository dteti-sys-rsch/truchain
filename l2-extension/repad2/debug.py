import pandas as pd
import numpy as np
from scipy import stats

# === LOAD DATA FIRST ===
df = pd.read_csv("filtered_100_700.csv", parse_dates=["Timestamp"])
df = df.sort_values(["Account", "Timestamp"])

def comprehensive_data_analysis(df):
    print("🔍 COMPREHENSIVE DATA ANALYSIS")
    print("=" * 60)
    
    # === 1. BASIC STATISTICS ===
    print("\n📊 1. BASIC DATASET STATISTICS:")
    print(f"   Total records: {len(df):,}")
    print(f"   Total accounts: {df['Account'].nunique():,}")
    print(f"   Date range: {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    print(f"   Total days: {(df['Timestamp'].max() - df['Timestamp'].min()).days} days")
    
    # === 2. TRANSACTION AMOUNT ANALYSIS ===
    print("\n💰 2. TRANSACTION AMOUNT ANALYSIS:")
    amounts = df['Amount Received'].astype(float)
    print(f"   Amount Statistics:")
    print(f"     Mean: {amounts.mean():.2f}")
    print(f"     Median: {amounts.median():.2f}")
    print(f"     Std: {amounts.std():.2f}")
    print(f"     Min: {amounts.min():.2f}")
    print(f"     Max: {amounts.max():.2f}")
    print(f"     Q1: {amounts.quantile(0.25):.2f}")
    print(f"     Q3: {amounts.quantile(0.75):.2f}")
    
    # Skewness and Kurtosis
    print(f"     Skewness: {amounts.skew():.2f} (>{1.0} = highly skewed)")
    print(f"     Kurtosis: {amounts.kurtosis():.2f} (>>3 = heavy-tailed)")
    
    # === 3. ACCOUNT ACTIVITY ANALYSIS ===
    print("\n👤 3. ACCOUNT ACTIVITY ANALYSIS:")
    account_stats = df.groupby('Account').agg({
        'Amount Received': ['count', 'mean', 'std', 'min', 'max'],
        'Timestamp': ['min', 'max']
    }).round(2)
    
    account_stats.columns = ['tx_count', 'amount_mean', 'amount_std', 'amount_min', 'amount_max', 'first_tx', 'last_tx']
    account_stats['tx_per_day'] = account_stats['tx_count'] / ((account_stats['last_tx'] - account_stats['first_tx']).dt.days + 1)
    
    print(f"   Transactions per account:")
    print(f"     Mean: {account_stats['tx_count'].mean():.1f}")
    print(f"     Median: {account_stats['tx_count'].median():.1f}")
    print(f"     Std: {account_stats['tx_count'].std():.1f}")
    print(f"     Min: {account_stats['tx_count'].min():.0f}")
    print(f"     Max: {account_stats['tx_count'].max():.0f}")
    
    # Account distribution by transaction count
    tx_bins = [0, 10, 50, 100, 500, 1000, float('inf')]
    tx_labels = ['1-10', '11-50', '51-100', '101-500', '501-1000', '1000+']
    account_stats['tx_bucket'] = pd.cut(account_stats['tx_count'], bins=tx_bins, labels=tx_labels)
    bucket_counts = account_stats['tx_bucket'].value_counts().sort_index()
    
    print(f"\n   Accounts by transaction count:")
    for bucket, count in bucket_counts.items():
        print(f"     {bucket}: {count} accounts ({count/len(account_stats)*100:.1f}%)")
    
    # === 4. TEMPORAL PATTERN ANALYSIS ===
    print("\n⏰ 4. TEMPORAL PATTERN ANALYSIS:")
    
    # Daily pattern
    daily_pattern = df.groupby(df['Timestamp'].dt.date).size()
    print(f"   Daily transaction pattern:")
    print(f"     Mean daily tx: {daily_pattern.mean():.1f}")
    print(f"     Std daily tx: {daily_pattern.std():.1f}")
    print(f"     CV (std/mean): {daily_pattern.std()/daily_pattern.mean():.2f} (<0.5 = stable)")
    
    # === 5. PATTERN DETECTION FOR LSTM ===
    print("\n🧠 5. LSTM PATTERN DETECTION ANALYSIS:")
    
    # Analyze top accounts in detail (min 20 transactions)
    qualified_accounts = account_stats[account_stats['tx_count'] >= 20]
    
    pattern_results = []
    for acc in qualified_accounts.index[:10]:  # Analyze first 10 qualified accounts
        acc_data = df[df['Account'] == acc].sort_values('Timestamp')
        amounts = acc_data['Amount Received'].values.astype(float)
        
        if len(amounts) > 10:
            # Auto-correlation (lag 1)
            autocorr = np.corrcoef(amounts[:-1], amounts[1:])[0,1] if len(amounts) > 1 else 0
            
            # Stationarity test (simple variance ratio)
            first_half = amounts[:len(amounts)//2]
            second_half = amounts[len(amounts)//2:]
            var_ratio = np.var(second_half) / np.var(first_half) if len(first_half) > 5 and len(second_half) > 5 else 1.0
            
            # Pattern strength (inverse of coefficient of variation of differences)
            diffs = np.diff(amounts)
            pattern_strength = 1 / (np.std(diffs) / (np.mean(np.abs(diffs)) + 1e-6)) if len(diffs) > 0 else 0
            
            pattern_results.append({
                'account': acc,
                'transactions': len(amounts),
                'autocorrelation': autocorr,
                'variance_ratio': var_ratio,
                'pattern_strength': pattern_strength
            })
    
    # Print pattern analysis
    if pattern_results:
        avg_autocorr = np.mean([r['autocorrelation'] for r in pattern_results])
        avg_pattern = np.mean([r['pattern_strength'] for r in pattern_results])
        
        print(f"   Pattern Analysis ({len(pattern_results)} qualified accounts):")
        print(f"     Average Auto-correlation: {avg_autocorr:.3f}")
        print(f"     Average Pattern Strength: {avg_pattern:.3f}")
        
        # Auto-correlation interpretation
        if avg_autocorr > 0.5:
            print("     ✅ EXCELLENT: Strong temporal patterns for LSTM")
        elif avg_autocorr > 0.3:
            print("     ✅ GOOD: Clear temporal patterns for LSTM")
        elif avg_autocorr > 0.1:
            print("     ⚠️  WEAK: Some patterns exist but weak")
        else:
            print("     ❌ POOR: Data appears random for LSTM")
            
        # Pattern strength interpretation
        if avg_pattern > 2.0:
            print("     ✅ EXCELLENT: Strong predictable patterns")
        elif avg_pattern > 1.0:
            print("     ✅ GOOD: Predictable patterns")
        else:
            print("     ⚠️  WEAK: Patterns may be hard to learn")
    
    # === 6. DATA QUALITY ASSESSMENT ===
    print("\n🎯 6. DATA QUALITY ASSESSMENT FOR REPAD:")
    
    # Check if enough data for LOOK_BACK
    suitable_for_lookback_3 = len(account_stats[account_stats['tx_count'] >= 10])
    suitable_for_lookback_10 = len(account_stats[account_stats['tx_count'] >= 30])
    suitable_for_lookback_50 = len(account_stats[account_stats['tx_count'] >= 100])
    
    print(f"   Accounts suitable for LOOK_BACK=3: {suitable_for_lookback_3}/{len(account_stats)} ({suitable_for_lookback_3/len(account_stats)*100:.1f}%)")
    print(f"   Accounts suitable for LOOK_BACK=10: {suitable_for_lookback_10}/{len(account_stats)} ({suitable_for_lookback_10/len(account_stats)*100:.1f}%)")
    print(f"   Accounts suitable for LOOK_BACK=50: {suitable_for_lookback_50}/{len(account_stats)} ({suitable_for_lookback_50/len(account_stats)*100:.1f}%)")
    
    # Recommendation
    if suitable_for_lookback_10 / len(account_stats) > 0.5:
        print("   💡 RECOMMENDATION: Use LOOK_BACK=10 (good balance)")
    elif suitable_for_lookback_3 / len(account_stats) > 0.7:
        print("   💡 RECOMMENDATION: Use LOOK_BACK=3 (most accounts suitable)")
    else:
        print("   💡 RECOMMENDATION: Consider LOOK_BACK=3 (limited data)")
    
    return account_stats, pattern_results

# === RUN ANALYSIS ===
print("🚀 Starting Comprehensive Data Analysis...")
account_stats, pattern_results = comprehensive_data_analysis(df)

# Show detailed results for sample accounts
if pattern_results:
    print("\n📋 SAMPLE ACCOUNT ANALYSIS:")
    for result in pattern_results[:5]:
        pattern_status = "STRONG" if result['autocorrelation'] > 0.3 else "WEAK"
        print(f"   Account {result['account']}: {result['transactions']} tx, "
              f"Auto-corr: {result['autocorrelation']:.3f} ({pattern_status})")
else:
    print("❌ No qualified accounts found for pattern analysis")
