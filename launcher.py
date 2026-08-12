import subprocess
import os

# Run your EXE in background
subprocess.Popen(["client.exe"], shell=True)

# Open image with default viewer
os.startfile("test.png")
