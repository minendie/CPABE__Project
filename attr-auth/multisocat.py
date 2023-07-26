import os
import subprocess
import signal


processes = []

processes.append(subprocess.Popen([
    "socat",   
    #verify server with ca-public-key.pem + TLS_1.3 
    "OPENSSL-LISTEN:1339,reuseaddr,fork,cert=aa.pem,cafile=ca-public-key.pem,verify=0",   
    "EXEC:\"python3 /home/attr-auth/receive_user_abekey.py\",stderr"
]))

processes.append(subprocess.Popen([
    "socat",
    #verify server with ca-public-key.pem + TLS_1.3
    "OPENSSL-LISTEN:1340,reuseaddr,fork,cert=aa.pem,cafile=ca-public-key.pem,verify=0",
    "EXEC:\"python3 /home/attr-auth/receive_user_attr.py\",stderr"
]))

processes.append(subprocess.Popen([
    "socat",
    #verify server with ca-public-key.pem + TLS_1.3
    "OPENSSL-LISTEN:2000,reuseaddr,fork,cert=aa.pem,cafile=ca-public-key.pem,verify=0",
    "EXEC:\"python3 /home/attr-auth/distribute_abe_publickey.py\",stderr"
    ],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE
))

processes.append(subprocess.Popen([
    "socat",
    #verify server with ca-public-key.pem + TLS_1.3
    "OPENSSL-LISTEN:2001,reuseaddr,fork,cert=aa.pem,cafile=ca-public-key.pem,verify=0",
    "EXEC:\"python3 /home/attr-auth/distribute_abe_privatekey.py\",stderr"
    ],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE
))


def terminate_processes():
    for process in processes:
        process.terminate()


signal.signal(signal.SIGTERM, terminate_processes)

for process in processes:
    process.wait()