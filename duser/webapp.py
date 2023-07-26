from flask import Flask, render_template, request, redirect, url_for
from decrypt_table import decrypt_datarow, get_key
import mysql.connector
from register_user import register_user
import os


app = Flask(__name__)

config = {
    'host':'democrypto.mysql.database.azure.com',
    'user':'demo',
    'password':'crypto@12345',
    'database':'testsql'
}                           

# Construct connection string

try:
    conn = mysql.connector.connect(**config)
    print("Connection established")
except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        print("Something is wrong with the user name or password")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
        print("Database does not exist")
    else:
        print(err)
#else:
#    cursor_cloud = conn.cursor()

cursor_cloud = conn.cursor()    

#auto create 2 users with different attributes 
users = {}


def setup():
    user1 = register_user(["HEAD-DIRECTOR", "CENTRAL", "PROV5"])
    user2 = register_user(["HEAD-DIRECTOR", "CIO"])
    users['admin'] = user1
    users['user'] = user2


@app.route("/", methods = ["GET", "POST"])
def homepage():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == "admin" and password == "admin":
            return redirect(url_for("userpage", uid = users["admin"]))
        elif username == "user" and password == "user":
            return redirect(url_for("userpage", uid = users["user"]))
    return render_template("index.html")


@app.route("/userpage/<uid>", methods = ["GET", "POST"])
def userpage(uid):
    if uid == users['admin']:
        attrs = ["HEAD-DIRECTOR", "CENTRAL", "PROV5"]
    elif uid == users["user"]:
        attrs = ["HEAD-DIRECTOR", "CIO"]
    user = {
        'uid': uid,
        'attrs': attrs
    }

    if request.method == "POST":
        table = request.form.get("tables")
        return redirect(url_for("viewtable", uid = uid, table = table))
    
    return render_template("userpage.html", user = user)


@app.route("/userpage/<uid>/<table>")
def viewtable(uid, table):
    get_key(uid)
    dec_data = decrypt_datarow(cursor_cloud, f"SELECT * FROM {table}")
    conn.commit()
    
    return render_template("viewtable.html", rows = [list(row) for row in dec_data])


if __name__ == "__main__":
    setup()
    app.run(debug=True, host='0.0.0.0', port=5001)
    #conn.close()
    #cursor_cloud.close()