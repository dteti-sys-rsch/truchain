import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    'font.size': 16,           
    'axes.titlesize': 16,      
    'axes.labelsize': 16,      
    'xtick.labelsize': 16,    
    'ytick.labelsize': 16,     
    'legend.fontsize': 16     
})

labels = ['L1', 'L2', 'L1 and L2']
valid_inputs = [200, 200, 200]
invalid_inputs = [50, 50, 50]
outputs = [200, 200, 200]

x = np.arange(len(labels)) 
width = 0.4

fig, ax = plt.subplots(figsize=(8, 6))

valid_input_bars = ax.bar(
    x - width/2, valid_inputs, width, label='Valid Input', color='#F7AD45'
)
invalid_input_bars = ax.bar(
    x - width/2, invalid_inputs, width, bottom=valid_inputs, label='Invalid Input',
    color='#F7AD45', hatch='//'
)
output_bars = ax.bar(
    x + width/2, outputs, width, label='Output', color='#BB3E00'
)

ax.set_ylabel('Number of Transactions')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend(loc='upper left', bbox_to_anchor=(0, 1), ncol=3, frameon=True)

ax.set_ylim(0, 300)
ax.yaxis.grid(True, linestyle='--', linewidth=0.5)

plt.tight_layout()
plt.savefig('success-rate.pdf', format='pdf', dpi=300, bbox_inches='tight')
