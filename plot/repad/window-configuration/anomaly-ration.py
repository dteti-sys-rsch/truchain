import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    'font.size': 16,
    'axes.titlesize': 18,
    'axes.labelsize': 16,
    'xtick.labelsize': 14,
    'ytick.labelsize': 14,
    'legend.fontsize': 13
})

# === DATA ===
thresholds = [1, 5, 7, 10, 50, 70, 100, 500, 700, 1000]
normal_anomaly_ratio = [0, 0.35, 0.5, 0.35, 0.3, 0.2, 0.2, 0.05, 0.05, 0.05]
outlier_anomaly_ratio = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
smurf_anomaly_ratio = [0, 1, 1, 1, 1, 0.98, 0.96, 0, 0, 0]

fig, ax = plt.subplots(figsize=(8, 6))
index = np.arange(len(thresholds))

ax.plot(index, normal_anomaly_ratio, marker='o', color='#BB3E00', linewidth=2, label='Normal Tx')
ax.plot(index, outlier_anomaly_ratio, marker='^', color='#F7AD45', linewidth=2, label='Outlier Tx')
ax.plot(index, smurf_anomaly_ratio, marker='s', color='#657C6A', linewidth=2, label='Smurf Tx')

ax.set_ylabel('Anomaly Ratio')
ax.set_xlabel('Window Size')
ax.set_xticks(index)
ax.set_xticklabels([str(t) for t in thresholds])
ax.set_xlim(-0.3, len(thresholds) - 0.7)
ax.set_ylim(-0.1, 1.2)

ax.legend(loc='upper center', bbox_to_anchor=(0.38, 1.00), ncol=3, frameon=True)
ax.grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
plt.savefig('8-6-window-anomaly-only.pdf', format='pdf', dpi=300, bbox_inches='tight')
plt.show()
