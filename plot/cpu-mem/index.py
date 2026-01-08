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

labels = ['L1', 'L2', 'L3']
cpu_usage = [23, 33, 65]
mem_usage = [310, 357, 516]  

x = np.arange(len(labels))
width = 0.35

# Aspect ratio 4:3
fig, ax1 = plt.subplots(figsize=(8, 6))

bars_cpu = ax1.bar(x - width/2, cpu_usage, width, label='CPU Usage', color='#F7AD45')
ax1.set_ylabel('CPU Usage (%)', color='black')
ax1.set_ylim(0, max(cpu_usage) + 10)
ax1.set_xticks(x)
ax1.set_xticklabels(labels)
ax1.tick_params(axis='y', labelcolor='black')  # Set CPU y-axis ticks to black

ax2 = ax1.twinx()
bars_mem = ax2.bar(x + width/2, mem_usage, width, label='Mem. Usage', color='#BB3E00')
ax2.set_ylabel('Memory Usage (MiB)', color='black')
ax2.set_ylim(0, max(mem_usage) + 50)
ax2.tick_params(axis='y', labelcolor='black')

fig.legend(loc="upper right", bbox_to_anchor=(0.32, 1.0), bbox_transform=ax1.transAxes)

plt.tight_layout()
plt.savefig('8-6-cpu-mem.pdf', format='pdf', dpi=300)
