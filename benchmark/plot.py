import matplotlib.pyplot as plt
import numpy as np
import json

with open('results.json') as f:
    results = json.load(f)
results = np.flip(results)

plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42

plt.boxplot(results, vert=False, showfliers=False)
plt.yticks(list(range(6)), np.flip([
    "(1) Setup",
    "(2) Export",
    "(3) Import",
    "(4) Generate",
    "(5) Revoke",
    ""
]))
plt.xlabel("Completion Time (ms)")
plt.title("Performance of MFDPG Features")

plt.savefig("performance.pdf", bbox_inches='tight')
