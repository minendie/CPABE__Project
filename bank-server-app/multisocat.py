import os
import subprocess
import signal


processes = []

processes.append(subprocess.Popen([
    "socat",
    #"-dddd",
    "TCP-LISTEN:1334,reuseaddr,fork",
    #"OPENSSL-LISTEN:1339,reuseaddr,fork,cert=aa.pem,verify=0",
    "EXEC:\"python3 /home/server/receive_revoke.py\",stderr"
]))


def terminate_processes():
    for process in processes:
        process.terminate()


signal.signal(signal.SIGTERM, terminate_processes)

for process in processes:
    process.wait()