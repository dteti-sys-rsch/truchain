import matplotlib.pyplot as plt

plt.rcParams.update({
    'font.size': 16,           
    'axes.titlesize': 18,      
    'axes.labelsize': 16,      
    'xtick.labelsize': 14,    
    'ytick.labelsize': 14,     
    'legend.fontsize': 13     
})

tps_values = [200, 400, 600, 800, 1000]
throughputs = {
    'conf1': [162, 160, 160, 158, 158],  
    'conf2': [440, 439, 439, 438, 438]
}
latencies = {
    'conf1': [1.3, 1.4, 2.7, 3.3, 3.5],
    'conf2': [0.4, 0.6, 0.9, 1.1, 1.2]
}

bar_width = 0.4  
index = range(len(tps_values))

fig, ax1 = plt.subplots(figsize=(8, 6))

bar_conf1 = ax1.bar([i - bar_width/2 for i in index], throughputs['conf1'], 
                 bar_width, label='L1 Throughput', color='#6986ce')
bar_conf2 = ax1.bar([i + bar_width/2 for i in index], throughputs['conf2'], 
                 bar_width, label='L2 Throughput', color='#2f5597')

ax2 = ax1.twinx()

ax1.set_xticks(index)
ax1.set_xticklabels(tps_values)

ax2.plot(index, latencies['conf1'], marker='o', color='#3D365C', linestyle='-', linewidth=2, label='L1 Latency')
ax2.plot(index, latencies['conf2'], marker='s', color='#7C4585', linestyle='-', linewidth=2, label='L2 Latency')

ax1.set_xlabel('Concurrent Connections for 30 Seconds')
ax1.set_ylabel('Throughput (req/s)', color='black')
ax2.set_ylabel('Latency (s)', color='black')

ax1.set_ylim(0, 520)
ax2.set_ylim(0, 5)

lines_labels = [*ax1.containers, *ax2.get_lines()]
labels = [bar.get_label() for bar in [bar_conf1, bar_conf2]] + [line.get_label() for line in ax2.get_lines()]
ax1.legend(lines_labels, labels, loc='upper center', bbox_to_anchor=(0.33, 1), ncol=2, frameon=True)

plt.tight_layout()
plt.savefig('tput-lat-l1-l2.pdf', format='pdf', dpi=300, bbox_inches='tight')
