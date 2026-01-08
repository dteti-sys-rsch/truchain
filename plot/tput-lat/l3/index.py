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

# Data
tps_values = [200, 400, 600, 800, 1000]
throughputs = {
    'l3': [550, 543, 540, 540, 539]
}
latencies = {
    'l3': [0.3, 0.7, 1.1, 1.4, 1.8]
}

bar_width = 0.4 
index = np.arange(len(tps_values))

fig, ax1 = plt.subplots(figsize=(8, 6))

bar_l3 = ax1.bar(index, throughputs['l3'], bar_width, label='L3 Processing Rate', color='#F7AD45')

ax2 = ax1.twinx()

ax1.set_xticks(index)
ax1.set_xticklabels(tps_values)

ax2.plot(index, latencies['l3'], marker='o', color='#3D365C', linestyle='-', linewidth=2, label='L3 Elapsed Time')

ax1.set_xlabel('Number of Transactions in a Batch')
ax1.set_ylabel('Processing Rate (req/s)', color='black')
ax2.set_ylabel('Elapsed Time (s)', color='black')

ax1.set_ylim(0, 620)
ax2.set_ylim(0, 2.5)

lines_labels = [*ax1.containers, *ax2.get_lines()]
labels = [bar.get_label() for bar in [bar_l3]] + [line.get_label() for line in ax2.get_lines()]
ax1.legend(lines_labels, labels, loc='upper center', bbox_to_anchor=(0.4, 1), ncol=2, frameon=True)

plt.tight_layout()
plt.savefig('tput-lat-l3.pdf', format='pdf', dpi=300, bbox_inches='tight')
