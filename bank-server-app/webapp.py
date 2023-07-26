from flask import Flask, render_template, request, redirect
import pyodbc
from encrypt_table import encrypt_datarow
import mysql.connector


config = {
    'host':'democrypto.mysql.database.azure.com',
    'user':'demo',
    'password':'crypto@12345',
    'database':'testsql'
}

app = Flask(__name__)
conn_db = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL Server};server=database,1433;UID=SA;PWD=Pa55w0rd;database=crypto_db;");  
cursor_db = conn_db.cursor()

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
else:
    cursor_cloud = conn.cursor()
    
    cursor_cloud.execute("DROP TABLE IF EXISTS TransactionLog;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Card;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Account;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Branch;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Customer;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Bank;")

    print("Finished dropping table (if existed).")
    #Create table
    cursor_cloud.execute("create table if not exists Bank (cipher_bankid varchar(100), cipher_bankname varchar(100), cipher_addr varchar(100), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists Customer (cipher_cusid varchar(200), cipher_cusname varchar(200), cipher_sex varchar(200), cipher_dob varchar(200), cipher_socialID varchar(200), cipher_email varchar(400), cipher_addr varchar(400),cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists Branch (cipher_branchid varchar(100), cipher_branchname varchar(100), cipher_addr varchar(100), cipher_bankid varchar(100), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists Account (cipher_accid varchar(100), cipher_accusrname varchar(100), cipher_accpass varchar(100), cipher_dopen varchar(100), cipher_ttmoney varchar(100), cipher_dvt varchar(100), cipher_cusid varchar(100), cipher_branchid varchar (100), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists Card (cipher_cardid varchar(100), cipher_start_day varchar(100), cipher_expire_day varchar(100), cipher_type varchar(100), cipher_cusid varchar(100), cipher_accid varchar(100), cipher_branchid varchar(100), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists TransactionLog (cipher_transid varchar(100), cipher_cardid varchar(100), cipher_moneytrans varchar(100), cipher_moneybalance varchar(100), cipher_content_trans varchar (200), cipher_recv_bank varchar(100), cipher_recv_acc varchar(100), cipher_date_trans varchar(100), cipher_time_trans varchar(100), cipher_dvt varchar(100), cipher_key varchar(4096));")
    


@app.route("/", methods = [ 'GET', 'POST' ])   #api for encryption
def main_page():
    if request.method == 'POST':
        table = request.form.get("tables")
        enc_data = encrypt_datarow(cursor_db, f"select * from {table}")
        sql_statement = ""
        if table=='Bank':
            sql_statement = f"INSERT INTO {table} (cipher_bankid, cipher_bankname,cipher_addr,cipher_key)  VALUES (%s, %s, %s, %s);"
        elif table == 'Customer':
            sql_statement = f"INSERT INTO {table} (cipher_cusid, cipher_cusname,cipher_sex,cipher_dob,cipher_socialID,cipher_email,cipher_addr,cipher_key)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s);"
        elif table == 'Branch':
            sql_statement = f"INSERT INTO {table} (cipher_branchid, cipher_branchname,cipher_addr,cipher_bankid,cipher_key)  VALUES (%s, %s, %s, %s, %s);"
        elif table == 'Account':
            sql_statement = f"INSERT INTO {table} (cipher_accid, cipher_accusrname,cipher_accpass,cipher_dopen,cipher_ttmoney,cipher_dvt,cipher_cusid,cipher_branchid,cipher_key)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);"
        elif table == 'Card':
            sql_statement = f"INSERT INTO {table} (cipher_cardid, cipher_start_day,cipher_expire_day,cipher_type,cipher_cusid,cipher_accid,cipher_cusid,cipher_branchid,cipher_key)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);"
        else:
            sql_statement = f"INSERT INTO {table} (cipher_transid, cipher_cardid,cipher_moneytrans,cipher_moneybalance,cipher_content_trans,cipher_recv_bank,cipher_recv_acc,cipher_date_trans,cipher_time_trans,cipher_dvt,cipher_key)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"

        cursor_cloud.executemany(sql_statement,enc_data)
        conn.commit()

        return f'Successfully encrypted table {table}!!!!'
    else:
        return render_template("index.html")


@app.route("/view/", methods = [ "GET", "POST" ])   #api for viewing tables in raw database 
def view():
    if request.method == "POST":
        table_ = request.form.get("tables")

        return redirect(f"/view/{table_}")
        #return render_template("view_table.html", rows=rows)
    else:
        return render_template("view_table.html", rows=None)
    

@app.route("/view/<table>")
def view_table(table):
    cursor_db.execute(f"select * from {table}")
    rows = cursor_db.fetchall()

    return render_template("view_table.html", rows=[list(row) for row in rows])
    

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
    cursor_db.close()
    conn_db.close()
    conn.close()
    cursor_cloud.close()