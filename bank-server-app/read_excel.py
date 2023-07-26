import os

import pymssql
import pyodbc


conn = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL Server};server=database,1433;UID=SA;PWD=Pa55w0rd;database=crypto_db;");  

cursor = conn.cursor()
query = input("Enter a query: ").strip()

cursor.execute(query)
rows = cursor.fetchall()
for row in rows:
    print(row)

conn.close()