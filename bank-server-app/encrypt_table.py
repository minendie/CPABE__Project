import os

import pymssql
import pyodbc
from pwn import remote, context
import os
import json
import base64


'''
Kan Yang, Xiaohua Jia 
 
| From: Expressive, Efficient, and Revocable Data Access Control for Multi-Authority Cloud Storage 
| Published in: Parallel and Distributed Systems, IEEE Transactions on  (Volume: 25,  Issue: 7) 
| Available From: http://ieeexplore.ieee.org/xpl/articleDetails.jsp?arnumber=6620875
| Notes: 

* type:      ciphertext-policy attribute-based encryption (public key)
* setting:   Pairing

:Authors:	artjomb
:Date:		07/2014
'''

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth

class MAABE(object):
    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)  #Create Secret Sharing Scheme
        self.group = groupObj    #:Prime order group
    
    def setup(self):
        '''Global Setup (executed by CA)'''
        #:In global setup, a bilinear group G of prime order p is chosen
        #:The global public parameters, GP and p, and a generator g of G. A random oracle H maps global identities GID to elements of G
    
        #:group contains 
        #:the prime order p is contained somewhere within the group object
        g = self.group.random(G1)
        #: The oracle that maps global identities GID onto elements of G
        #:H = lambda str: g** group.hash(str)
        H = lambda x: self.group.hash(x, G1)
        a = self.group.random()
        b = self.group.random()
        g_a = g ** a
        g_b = g ** b
        GPP = {'g': g, 'g_a': g_a, 'g_b': g_b}
        GMK = {'a': a, 'b': b}
        
        return (GPP, GMK)

    
    def registerUser(self, GPP):
        '''Generate user keys (executed by the user).'''
        g = GPP['g']
        ugsk1 = self.group.random()
        ugsk2 = self.group.random()
        ugpk1 = g ** ugsk1
        ugpk2 = g ** ugsk2
        
        
        return ((ugpk1, ugsk2), { 'pk': ugpk2, 'sk': ugsk1 }) # (private, public)

    
    def setupAuthority(self, GPP, authorityid, attributes, authorities):
        '''Generate attribute authority keys (executed by attribute authority)'''
        if authorityid not in authorities:
            alpha = self.group.random()
            beta = self.group.random()
            gamma = self.group.random()
            SK = {'alpha': alpha, 'beta': beta, 'gamma': gamma}
            PK = {
                'e_alpha': pair(GPP['g'], GPP['g']) ** alpha, 
                'g_beta': GPP['g'] ** beta, 
                'g_beta_inv': GPP['g'] ** ~beta
            }
            authAttrs = {}
            authorities[authorityid] = (SK, PK, authAttrs)
        else:
            SK, PK, authAttrs = authorities[authorityid]
        for attrib in attributes:
            if attrib in authAttrs:
                continue
            versionKey = self.group.random() # random or really 'choose' ?
            h = GPP['H'](attrib)
            pk = h ** versionKey
            authAttrs[attrib] = {
                'VK': versionKey, #secret
                'PK1': pk, #public
                'PK2': pk ** SK['gamma'] #public
            }
            PK1 = groupObj.serialize(authAttrs[attrib]['PK1'])
            #print("PK1: ", PK1)
            if debug == True:
                print (type(authAttrs[attrib]['PK1']))
                
                
            
            
        return (SK, PK, authAttrs)

     
    def keygen(self, GPP, authority, attribute, userObj, USK = None):
        '''Generate user keys for a specific attribute (executed on attribute authority)'''
        if 't' not in userObj:
            userObj['t'] = self.group.random() #private to AA
        t = userObj['t']
        
        ASK, APK, authAttrs = authority
        u = userObj
        if USK is None:
            USK = {}
        if 'K' not in USK or 'KS' not in USK or 'AK' not in USK:
            USK['K'] = \
                (GPP['g'] ** ASK['alpha']) * \
                (GPP['g_a'] ** u['sk']) * \
                (GPP['g_b'] ** t)
            USK['KS'] = GPP['g'] ** t
            USK['AK'] = {}
        AK = (u['pk'] ** (t * ASK['beta'])) * \
            ((authAttrs[attribute]['PK1'] ** ASK['beta']) ** (u['sk'] + ASK['gamma']))
        USK['AK'][attribute] = AK
        '''
        
            '''
        return USK

    
    def encrypt(self, GPP, policy_str, k, authority):
        '''Generate the cipher-text from the content(-key) and a policy (executed by the content owner)'''
        #GPP are global parameters
        #k is the content key (group element based on AES key)
        #policy_str is the policy string
        #authority is the authority tuple
        
        _, APK, authAttrs = authority
        
        policy = self.util.createPolicy(policy_str)
        secret = self.group.random()
        shares = self.util.calculateSharesList(secret, policy)
        shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in shares])
        
        C1 = k * (APK['e_alpha'] ** secret)
        C2 = GPP['g'] ** secret
        C3 = GPP['g_b'] ** secret
        C = {}
        CS = {}
        D = {}
        DS = {}
        
        for attr, s_share in shares.items():
            k_attr = self.util.strip_index(attr)
            r_i = self.group.random()
            attrPK = authAttrs[attr]
            C[attr] = (GPP['g_a'] ** s_share) * ~(attrPK['PK1'] ** r_i)
            CS[attr] = GPP['g'] ** r_i
            D[attr] = APK['g_beta_inv'] ** r_i
            DS[attr] = attrPK['PK2'] ** r_i
        
        return {'C1': C1, 'C2': C2, 'C3': C3, 'C': C, 'CS': CS, 'D': D, 'DS': DS, 'policy': policy_str}

        
    def decrypt(self, GPP, CT, user):
        '''Decrypts the content(-key) from the cipher-text (executed by user/content consumer)'''
        UASK = user['authoritySecretKeys']
        USK = user['keys']
        usr_attribs = list(UASK['AK'].keys())
        policy = self.util.createPolicy(CT['policy'])
        pruned = self.util.prune(policy, usr_attribs)
        if pruned == False:
            return False
        coeffs = self.util.getCoefficients(policy)
        
        first = pair(CT['C2'], UASK['K']) * ~pair(CT['C3'], UASK['KS'])
        n_a = 1
        
        ugpk1, ugsk2 = USK
        e_gg_auns = 1
        
        for attr in pruned:
            x = attr.getAttributeAndIndex()
            y = attr.getAttribute()
            temp = \
                pair(CT['C'][y], ugpk1) * \
                pair(CT['D'][y], UASK['AK'][y]) * \
                pair(CT['CS'][y], ~(UASK['KS'] ** ugsk2)) * \
                ~pair(GPP['g'], CT['DS'][y])
            e_gg_auns *= temp ** (coeffs[x] * n_a)
        return CT['C1'] / (first / e_gg_auns)

    
    def ukeygen(self, GPP, authority, attribute, userObj):
        '''Generate update keys for users and cloud provider (executed by attribute authority?)'''
        ASK, _, authAttrs = authority
        oldVersionKey = authAttrs[attribute]['VK']
        newVersionKey = oldVersionKey
        while oldVersionKey == newVersionKey:
            newVersionKey = self.group.random()
        authAttrs[attribute]['VK'] = newVersionKey
        
        u_uid = userObj['sk']
        UKs = GPP['H'](attribute) ** (ASK['beta'] * (newVersionKey - oldVersionKey) * (u_uid + ASK['gamma']))
        UKc = (newVersionKey/oldVersionKey, (oldVersionKey - newVersionKey)/(oldVersionKey * ASK['gamma']))
        
        authAttrs[attribute]['PK1'] = authAttrs[attribute]['PK1'] ** UKc[0]
        authAttrs[attribute]['PK2'] = authAttrs[attribute]['PK2'] ** UKc[0]
        
        return { 'UKs': UKs, 'UKc': UKc }

    
    def skupdate(self, USK, attribute, UKs):
        '''Updates the user attribute secret key for the specified attribute (executed by non-revoked user)'''
        USK['AK'][attribute] = USK['AK'][attribute] * UKs

    
    def ctupdate(self, GPP, CT, attribute, UKc):
        '''Updates the cipher-text using the update key, because of the revoked attribute (executed by cloud provider)'''
        CT['C'][attribute] = CT['C'][attribute] * (CT['DS'][attribute] ** UKc[1])
        CT['DS'][attribute] = CT['DS'][attribute] ** UKc[0]

#-------------------------------------
def Deserialize_GPP(jsGPP):
    
    # GPP nhận GPP từ CA 
    # -----------------------------------   
    GPP = {}
    H = lambda x: groupObj.hash(x, G1)
    GPP = {'g': groupObj.deserialize(jsGPP['g'].encode()),
            'g_a': groupObj.deserialize(jsGPP['g_a'].encode()),
            'g_b': groupObj.deserialize(jsGPP['g_b'].encode()),
            }
    GPP['H'] = H
    
    print ("GPP: ", GPP)
    return GPP


def Deserialize_User_Skey_CA(jsU):
    user_PR = {}
    user_PR ['uid'] = jsU['uid']
    user_PR['uSK']= (groupObj.deserialize(jsU['uSK'][0].encode() ),groupObj.deserialize(jsU['uSK'][1].encode()))

    #Id = ID['id']
    #USK = ( )
    print("UserPR: ",user_PR)
    #Ucert  # doi gen cert 
    return user_PR # bổ sung thêm Ucert


def Deserialize_User_Skey_AA(uSK_aa):
    authorityAttributes = ['HEAD-DIRECTOR', 'DIVISIONAL MANAGEMENT', 'CEO', 'CTO', 'CIO', 'BRANCH MANANGER', 'ASSISTANT OF BM', 'CUSTOMER SERVICE', 'RELATIONSHIP MANAGEMENT', 'CONSULTANT', 'CENTRAL', 'PROV1', 'PROV2', 'PROV3', 'PROV4', 'PROV5']
    uSK = {'K': groupObj.deserialize(uSK_aa['K'].encode()),
            'KS': groupObj.deserialize(uSK_aa['KS'].encode())
    }
    AK = {}
    for attrib in authorityAttributes: 
        AK[attrib] = groupObj.deserialize(uSK_aa['AK'][attrib].encode())
    uSK ['AK'] = AK
    print (uSK)


def Deserialize_User_Pkey_AA(jsAuth):
    auth_attributes = jsAuth['authr']
    authority = {}
    SK = {}
       
    APK = jsAuth['PK'][1]
    APK = { 'e_alpha': groupObj.deserialize(APK['e_alpha'].encode()),
            'g_beta': groupObj.deserialize(APK['g_beta'].encode()),
            'g_beta_inv': groupObj.deserialize(APK['g_beta_inv'].encode())
    }
    PK = jsAuth['PK'][2]
    for attrib in auth_attributes :
        PK1 = groupObj.deserialize(PK[attrib]['PK1'].encode())
        PK2 = groupObj.deserialize(PK[attrib]['PK2'].encode())
        PK [attrib] = {'PK1': PK1,'PK2':PK2}
    authority = (SK, APK, PK)
    #print ("authority: ", authority)
    return authority
    


def Deserialize_USK(jsUSK, user_attributes):
    USK = {}
    USK={'K': groupObj.deserialize(jsUSK['K'].encode()),
         'KS': groupObj.deserialize(jsUSK['KS'].encode())}
    tmpUSK = {}
    for attrib in user_attributes:
        tmpUSK[attrib] = groupObj.deserialize(jsUSK['AK'][attrib].encode())
    USK['AK'] = tmpUSK
    print("USK: ", USK)
    return USK


conn_db = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL Server};server=database,1433;UID=SA;PWD=Pa55w0rd;database=crypto_db;");  

cursor_db = conn_db.cursor()



# print("USER NODE: ")
groupObj = PairingGroup('SS512')
maabe = MAABE(groupObj=groupObj)
GPP = {}
user1_private_CA = {}
# nhan GPP
if os.path.isfile("global-params.json"): # nhan tu CA
    jsGPP = {}
    with open ("global-params.json", "r") as f:
        jsGPP = json.load(f)
    f.close()
    GPP = Deserialize_GPP(jsGPP)
    
uid = open('uid').read()

# Nhan usk_ca
if os.path.isfile(f"user-privatekeyabe-{uid}.json"):  # nhan tu CA de decrypt
    jsU_PR = {}
    with open(f"user-privatekeyabe-{uid}.json", "r") as f:
        jsU_PR = json.load(f)
    f.close()
    user1_private_CA = Deserialize_User_Skey_CA(jsU_PR)


#list luu tap thuoc tinh cua user:
user_attributes = ["HEAD-DIRECTOR", "CENTRAL", "PROV5"]    # vi du nhu vay   
#print (len(user_attributes))

#send file user info
if not os.path.isfile (f"user-info-{uid}.json"):   # file nay gui toi AA
    jsUser = {} 
    attr_dict = {}
    jsUser['uid'] = uid # user1_private_CA['uid'] 
    attr_dict = user_attributes
    jsUser['attributes'] = attr_dict
    # print(f"user-info-{uid}: {jsUser}")
    with open (f"user_info-{uid}.json", "w") as f:
        json.dump(jsUser, f)
    f.close()

# querry abe public key from AA

context.log_level = 'Debug'
r = remote("attr-auth", 2000, ssl=True)

jsAuth = json.loads(r.recvline().strip().decode())
authority_enc = Deserialize_User_Pkey_AA(jsAuth)

r.close()



from aes_gcm_128_helpers import encrypt_AES_GCM
from cp_abe_services import deserialize_GPP, serialize_ciphertext
import mysql.connector


def encrypt_datarow(cursor, str_querry):   #cái này gửi lên cloud 
    cursor.execute(str_querry)
    rows = cursor.fetchall()
    enc_data = []
    
    for row in rows:
        #get data in 1 row of rows
        my_tuple = ()
        #plaintext = ""
        key = groupObj.random(GT)
        #print("key_goc:", key)
        key_AES = groupObj.serialize(key)[:16]
        policy_str = '((HEAD-DIRECTOR or CIO) and (CENTRAL or PROV5))'    #Important 
        for i in range(len(row)):
            ret_ciphertext = encrypt_AES_GCM(str(row[i]).encode(), key_AES) # <byte>
            b64_ret_ciphertext = base64.b64encode(ret_ciphertext) # <byte> of b64
            b64_ret_ciphertext = b64_ret_ciphertext.decode() # string
            my_tuple += (b64_ret_ciphertext,)

        encrypted_key = encrypt_content_key(key, policy_str)
        b64_encrypted_key = base64.b64encode(encrypted_key.encode()).decode()
        my_tuple += (b64_encrypted_key,)
        enc_data.append(my_tuple)
       
       

    return enc_data


def encrypt_content_key(key, policy_str):
    # key pairing group GT
    maabe = MAABE(groupObj=groupObj)
    
    authority = authority_enc

    jsGPP = {}
    if os.path.isfile("global-params.json"): #nhan tu CA
        with open ("global-params.json", "r") as f:
            jsGPP = json.load(f)
        f.close()
    GPP = deserialize_GPP(jsGPP)
    k = maabe.encrypt(GPP, policy_str, key, authority)
    k = serialize_ciphertext(k) # convert k to string
    
    # print(k)
    
    return k


config = {
    'host':'democrypto.mysql.database.azure.com',
    'user':'demo',
    'password':'crypto@12345',
    'database':'testsql'
}                           

# Construct connection string
'''
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
# Drop previous table of same name if one exists

    cursor_cloud.execute("DROP TABLE IF EXISTS TransactionLog;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Card;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Account;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Branch;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Customer;")
    cursor_cloud.execute("DROP TABLE IF EXISTS Bank;")

    print("Finished dropping table (if existed).")
    #Create table 
    cursor_cloud.execute("create table if not exists Account (cipher_data varchar(200), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists Customer (cipher_data varchar(200), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists Bank (cipher_data varchar(200), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists Branch (cipher_data varchar(200), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists TransactionLog (cipher_data varchar(200), cipher_key varchar(4096));")
    cursor_cloud.execute("create table if not exists Card (cipher_data varchar(200), cipher_key varchar(4096))")

    enc_data = encrypt_datarow(cursor_db,'select * from Bank')
    for i in range (0, len(enc_data)):
        cursor_cloud.execute("INSERT INTO Bank (cipher_data, cipher_key) VALUES ('%s', '%s');" % (enc_data[i][0], enc_data[i][1]))
    #enc_data = encrypt_datarow(cursor_db,'select * from Branch')
    #for i in range (0, len(enc_data)):
    #    cursor_cloud.execute("INSERT INTO Branch (cipher_data, cipher_key) VALUES ('%s', '%s');" % (enc_data[i][0], enc_data[i][1]))
    #enc_data = encrypt_datarow(cursor_db,'select * from Customer')
    #for i in range (0, len(enc_data)):
    #    cursor_cloud.execute("INSERT INTO Customer (cipher_data, cipher_key) VALUES ('%s', '%s');" %(enc_data[i][0], enc_data[i][1]))
    #enc_data = encrypt_datarow(cursor_db,'select * from Account')
    #for i in range (0, len(enc_data)):
    #    cursor_cloud.execute("INSERT INTO Account (cipher_data, cipher_key) VALUES ('%s', '%s');" %(enc_data[i][0], enc_data[i][1]))
    #enc_data = encrypt_datarow(cursor_db,'select * from Card')
    #for i in range (0, len(enc_data)):
    #    cursor_cloud.execute("INSERT INTO Card (cipher_data, cipher_key) VALUES ('%s', '%s');" %(enc_data[i][0], enc_data[i][1]))
    #enc_data = encrypt_datarow(cursor_db,'select * from TransactionLog')
    #for i in range (0, len(enc_data)):
    #    cursor_cloud.execute("INSERT INTO TransactionLog (cipher_data, cipher_key) VALUES ('%s', '%s');" %(enc_data[i][0], enc_data[i][1]))


    #insert and enc to send to cloud
    
    table = input("Enter table: ")
    values = ()
    if table == 'Bank':
        values = inputBank(table, cursor_db)
        cursor_cloud.execute(f"INSERT INTO {table} (cipher_data, cipher_key) VALUES ('%s, %s');" %(values[0], values[1]))

    elif  table == 'Account':
        values = inputAccount(table, cursor_db)
        cursor_cloud.execute(f"INSERT INTO {table} (cipher_data, cipher_key) VALUES ('%s, %s');" %(values[0], values[1]))

    elif table == 'Branch':
        values = inputBranch(table, cursor_db)
        cursor_cloud.execute(f"INSERT INTO {table} (cipher_data, cipher_key) VALUES ('%s, %s');" %(values[0], values[1]))

    elif  table == 'Customer':
        values = inputCustomer(table, cursor_db)
        cursor_cloud.execute(f"INSERT INTO {table} (cipher_data, cipher_key) VALUES ('%s, %s');" %(values[0], values[1]))

    elif table == 'Card':
        values = inputCard(table, cursor_db)
        cursor_cloud.execute(f"INSERT INTO {table} (cipher_data, cipher_key) VALUES ('%s, %s');" %(values[0], values[1]))

    else:
        values = inputTransactionLog(table, cursor_db)
        cursor_cloud.execute(f"INSERT INTO {table} (cipher_data, cipher_key) VALUES ('%s, %s');" %(values[0], values[1]))
    '''

    # dong ket noi toi cloud    
    #conn.commit()
    #cursor_cloud.close()
    #conn.close()

cursor_db.close()
conn_db.close()

#Phần này để kết nối với database lấy data raw xử lý 

