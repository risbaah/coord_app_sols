import numpy as np
import glob

files = glob.glob("captured_traces/trace_*.npy")

best_password = ""
best_energy   = 0

for f in files:
    password = f.split("trace_")[1].replace(".npy", "")

    trace  = np.load(f)
    energy = np.sum(trace ** 2)
    if energy > best_energy:
        best_energy   = energy
        best_password = password

print(f"Password: {best_password} and energy if you want ig (energy: {best_energy})")
