import matplotlib.pyplot as plt
import numpy as np
import sys

x      = list()
angr   = list()
ghidra = list()

i   = 0
fin = open(sys.argv[1], "r")
for line in fin:
    line = line.strip()
    if line == "":
        continue
    addr, angr_bb, ghidra_bb = line.split(", ")
    angr_bb   = int(angr_bb)
    ghidra_bb = int(ghidra_bb)
    if not (angr_bb < 100 and ghidra_bb < 100):
        # filter out small functions
        continue

    x.append(i)
    angr.append(angr_bb)
    ghidra.append(ghidra_bb)
    i += 1
fin.close()

x = np.array(x)

ax = plt.subplot(111)
ax.bar(x-0.2, angr, width=0.4, color='r', align='center')
ax.bar(x+0.2, ghidra, width=0.4, color='g', align='center')

print(len(x))
plt.show()
