import json
import os
import datetime
import uuid


b_log = input()
now = datetime.datetime.now() 
jslog = json.loads(b_log)  

print(b_log)

msg = f"[NOTIFICATION] Received log from {jslog['id']} at " + str(now) + ": " + f"{jslog['log']}"

print (msg)

if not os.path.isfile("/home/log_node/LogFile"):
    with open ("/home/log_node/LogFile", "a") as file:
        file.write(msg)
        file.write("\n")
    file.close()
else:
    with open("/home/log_node/LogFile", "a") as file:
        file.write(msg)
        file.write("\n")
    file.close()



