jsUKc = input("Input updatekey_cloud: ")

with open("updatekey_cloud.json", "w") as f:
    f.write(jsUKc)
    print(jsUKc)

f.close()