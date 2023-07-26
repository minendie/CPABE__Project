import os
import subprocess
import signal


processes = []
#port listenning to aa register
processes.append(subprocess.Popen([
    "socat",    
    "OPENSSL-LISTEN:1337,reuseaddr,fork,cert=ca.pem,verify=0",   #TLS_1.3
    "EXEC:\"python3 /home/cert-auth/register_aa.py\",stderr"
]))

#port listenning to user register
processes.append(subprocess.Popen([
    "socat",    
    "OPENSSL-LISTEN:1338,reuseaddr,fork,cert=ca.pem,verify=0",   #TLS_1.3
    "EXEC:\"python3 /home/cert-auth/register_user.py\",stderr"
    ],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE
))


def terminate_processes():
    for process in processes:
        process.terminate()


signal.signal(signal.SIGTERM, terminate_processes)

for process in processes:
    process.wait()


