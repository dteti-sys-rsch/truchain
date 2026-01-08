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
    'conf1': [149, 147, 142, 140, 140],  
    'conf2': [420, 414, 410, 410, 407]
}
latencies = {
    'conf1': [1.4, 1.7, 2.7, 3.8, 4],
    'conf2': [0.5, 0.7, 0.9, 1.1, 1.4]
}

bar_width = 0.4  
index = range(len(tps_values))

fig, ax1 = plt.subplots(figsize=(8, 6))

bar_conf1 = ax1.bar([i - bar_width/2 for i in index], throughputs['conf1'], 
                 bar_width, label='Conf. 1 Throughput', color='#F7AD45')
bar_conf2 = ax1.bar([i + bar_width/2 for i in index], throughputs['conf2'], 
                 bar_width, label='Conf. 2 Throughput', color='#BB3E00')

ax2 = ax1.twinx()

ax1.set_xticks(index)
ax1.set_xticklabels(tps_values)

ax2.plot(index, latencies['conf1'], marker='o', color='#3D365C', linestyle='-', linewidth=2, label='Conf. 1 Latency')
ax2.plot(index, latencies['conf2'], marker='s', color='#7C4585', linestyle='-', linewidth=2, label='Conf. 2 Latency')

ax1.set_xlabel('Concurrent Connections for 30 Seconds')
ax1.set_ylabel('Throughput (req/s)', color='black')
ax2.set_ylabel('Latency (s)', color='black')

ax1.set_ylim(0, 500)
ax2.set_ylim(0, 5)

lines_labels = [*ax1.containers, *ax2.get_lines()]
labels = [bar.get_label() for bar in [bar_conf1, bar_conf2]] + [line.get_label() for line in ax2.get_lines()]
ax1.legend(lines_labels, labels, loc='upper center', bbox_to_anchor=(0.38, 1), ncol=2, frameon=True)

plt.tight_layout()
plt.savefig('tput-lat-conf1-conf2.pdf', format='pdf', dpi=300, bbox_inches='tight')
