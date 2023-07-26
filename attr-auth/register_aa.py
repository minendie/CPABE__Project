from pwn import remote, context
import json
import subprocess

context.log_level = 'Debug'


#send log
jsLog = {'id': 'aa-new', 'log': 'register to CA to request aid and cert'}
strLog = json.dumps(jsLog)
s_log = remote("log_node", 1335)
s_log.sendline(strLog.encode('utf-8'))
s_log.close()


#register_aa
s = remote("cert-auth", 1337, ssl=True)

with open("aa-csr.pem", "rb") as f:
    data = f.read().split(b'\n')
    for line in data:
        # print(line)
        s.sendlineafter(b"Input: ", line)

aid = s.recvline().strip().decode().split(' ')[1]
print(aid)

keys = []
while True:
    try:
        line = s.recvline().strip().decode()
    except EOFError:
        break
    keys.append(line)

GPP = keys[0]

public_key = []
ca_public_key = []

i = 1

while "END CERTIFICATE" not in keys[i]:
    public_key.append(keys[i])
    i += 1
public_key.append(keys[i])    
i += 1
while "END CERTIFICATE" not in keys[i]:
    ca_public_key.append(keys[i])
    i += 1
ca_public_key.append(keys[i])

with open("aid", "w") as f:
    f.write(aid)
f.close()

with open(f"global-params.json", "w") as f:
    f.write(GPP)
f.close()

with open(f"aa-public-key-{aid}.pem", "w") as f:
    f.write("\n".join(public_key) + "\n")
f.close()

with open(f"ca-public-key.pem", "w") as f:
    f.write("\n".join(ca_public_key) + "\n")
f.close()

s.close()

with open("aa-private-key.pem") as f:
    first = f.read()
f.close()

with open(f"aa-public-key-{aid}.pem") as f:
    second = f.read()
f.close()

with open("aa.pem", "w") as f:
    f.write(first + second)
f.close()
