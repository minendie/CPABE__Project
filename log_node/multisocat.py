import os
import subprocess
import signal


processes = []

processes.append(subprocess.Popen([
    "socat",    
    "TCP-LISTEN:1335,reuseaddr,fork",
    "EXEC:\"python3 /home/log_node/savelog.py\",stderr"
]))



def terminate_processes():
    for process in processes:
        process.terminate()


signal.signal(signal.SIGTERM, terminate_processes)

for process in processes:
    process.wait()