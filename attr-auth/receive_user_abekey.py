import os
import json
from pwn import remote, context


with open("aid", "r") as f:
    aid = f.read()
f.close()

context.log_level = 'Debug'

uid = input("uid: ")

js = input("user-publickeyabe: ")

if not os.path.exists(f"/home/user-{uid}"):
    os.mkdir(f"/home/user-{uid}")

with open(f"/home/user-{uid}/user-publickeyabe-{uid}.json", "w") as f:
    f.write(js)
f.close()

#send log

print("aid", aid)
#jsLog = {}
jsLog = {
    'id': f'aa-{aid}', 
    'log': f'received user-publickeyabe-{uid} from CA.'
}
strLog = json.dumps(jsLog)

context.log_level = "Debug"

s_log = remote("log_node", 1335)
s_log.sendline(strLog.encode('utf-8'))
print(s_log.recvline())
s_log.close()


