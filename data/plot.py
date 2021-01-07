import numpy as np
import matplotlib.pyplot as plt

# Fixing random state for reproducibility
np.random.seed(19680801)


N = 10
x = [10, 22, 31, 40, 52, 61, 70, 82, 91, 100]
y = [11, 27, 38, 49, 65, 77, 88, 103, 115, 127]
y1 = [5, 12, 17, 22, 29, 34, 40, 46, 50, 55]

fig = plt.figure()
plt.scatter(x, y1, alpha=0.5)
fig.suptitle('Time for Replicas to Construct Signature', fontsize=18)
plt.xlabel('Number of Replicas', fontsize=14)
plt.ylabel('Latency (ms)', fontsize=12)
fig.savefig('replica.jpg')