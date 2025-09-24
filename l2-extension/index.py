import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

df = pd.read_excel("lite.ods", engine="odf")

df['Timestamp'] = pd.to_datetime(df['Timestamp'])

df['Amount'] = df['Amount Paid']

features = []

for acc, group in df.groupby("Account"):
    avg_amount = group['Amount'].mean()
    std_amount = group['Amount'].std() if group['Amount'].count() > 1 else 0
    freq = len(group)
    uniq_counterparty = group['To Bank'].nunique() + group['To Account'].nunique()

    payment_div = group['Payment Format'].nunique()

    features.append({
        "Account": acc,
        "avg_amount": avg_amount,
        "std_amount": std_amount,
        "freq": freq,
        "uniq_counterparty": uniq_counterparty,
        "payment_div": payment_div
    })

feat_df = pd.DataFrame(features)

X = feat_df.drop(columns=["Account"])
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# N NUMBER HERE
kmeans = KMeans(n_clusters=3, random_state=42)
feat_df['cluster'] = kmeans.fit_predict(X_scaled)

print(feat_df.head())

centroids = kmeans.cluster_centers_
print("Centroids (scaled):\n", centroids)
