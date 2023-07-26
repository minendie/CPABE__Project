import mysql.connector
import base64
from cp_abe_services import ct_update
#---------
#connect to cloud sql
config = {
    'host':'democrypto.mysql.database.azure.com',
    'user':'demo',
    'password':'crypto@12345',
    'database':'testsql'
}

list_table = ['Bank']

def update_ciphertext():
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
        for table in list_table:
            print(f"updating cipher on {table} table")
            str_sql_querry = f"select cipher_key from {table};"
            cursor_cloud.execute(str_sql_querry)
            # toan bo dong key duoc truy van xuong de update
            rows = cursor_cloud.fetchall()
            #update_list_row = []
            #r1 = ""
            for row in rows:
                #print(row)
                encrypted_key= row[0] 
                print("ROW0:", row[0])
                 # base64.b64encode(key).decode() voi key la byte.
                #print(row[0])
                encrypted_key = base64.b64decode(encrypted_key.encode()).decode()  
                #encrypted_key1 = deserialize_ciphertext(encrypted_key)
                #print(encrypted_key1)
                CTU = ct_update(encrypted_key)
                CTU = base64.b64encode(CTU.encode()).decode()
                print("CTU: ", CTU)
                print(CTU == row[0])
                update_sql = f"update {table} set cipher_key = '{CTU}' where cipher_key = '{row[0]}'"
                cursor_cloud.execute(update_sql)
                #update_list_row.append(CTU)
            
            #for index in range(len(update_list_row)):
                #str_sql_querry = f"update {table} set cipher_key = '{update_list_row[index]}';"
                #print(str_sql_querry)
                
    conn.commit()
    cursor_cloud.close()
    conn.close()

     

                      

# Construct connection string

if __name__ == '__main__':
    update_ciphertext()
    
        





