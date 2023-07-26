uid = input("uid: ")

attributes = input("attributes: ")

with open(f"/home/user-{uid}/attributes.json", "w") as f:
    f.write(attributes)

f.close()