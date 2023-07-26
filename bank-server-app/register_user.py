from pwn import remote, context
import os
import json


context.log_level = 'Debug'


jsLog = {'id': 'bank server', 'log': 'register to CA to request uid and cert.'}
strLog = json.dumps(jsLog)
s_log = remote("log_node", 1335)
s_log.sendline(strLog.encode('utf-8'))
s_log.close()

s = remote("cert-auth", 1338, ssl=True)

with open("user-csr.pem", "rb") as f:
    data = f.read().split(b'\n')
    for line in data:
        s.sendlineafter(b"Input: ", line)

uid = s.recvline().strip().decode().split(' ')[1]
print(uid)

keys = []
while True:
    try:
        line = s.recvline().strip().decode()
    except EOFError:
        break
    keys.append(line)

GPP = keys[0]

public_key = []

i = 1

while "END CERTIFICATE" not in keys[i]:
    public_key.append(keys[i])
    i += 1

public_key.append(keys[i])

abe_private_key = keys[i+1]

with open("uid", "w") as f:
    f.write(uid)
f.close()

with open(f"global-params.json", "w") as f:
    f.write(GPP)
f.close()

with open(f"user-public-key-{uid}.pem", "w") as f:
    f.write("\n".join(public_key) + "\n")
f.close()

with open(f"user-privatekeyabe-{uid}.json", "w") as f:
    f.write(abe_private_key)
f.close()

#list luu tap thuoc tinh cua user:
user_attributes = ["HEAD-DIRECTOR", "CENTRAL", "PROV5"]    # vidu nhu vay   
#print (len(user_attributes))

#send file user info
if not os.path.isfile (f"user-info-{uid}.json"):   #file nay gui toi AA
    jsUser = {} 
    attr_dict = {}
    jsUser['uid'] = uid # user1_private_CA['uid'] 
    attr_dict = user_attributes
    jsUser['attributes'] = attr_dict
    # print(f"user_info: ", jsUser)
    with open (f"user-info-{uid}.json", "w") as f:
        json.dump(jsUser, f)
    f.close()

s.close()

s = remote("attr-auth", 1340, ssl=True)
with open(f"user-info-{uid}.json") as f:
    data = f.read()
    s.sendlineafter(b"uid: ", uid.encode())
    s.sendlineafter(b"attributes: ", data.encode())
s.close()