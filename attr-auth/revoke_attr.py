from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from pwn import remote, context


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
                
                #print (authAttrs[attrib]['PK1'])
                #print (authAttrs[attrib]['PK2'])            
        
            
            
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

    
    def ukeygen(self, GPP, authority, attribute, userObj, newVerkey): #authority{attrib: {VK, PK1, PK2}} la tap con cua authorities
        '''Generate update keys for users and cloud provider (executed by attribute authority?)'''
        ASK, _, authAttrs = authority
        oldVersionKey = authAttrs[attribute]['VK']
        #newVersionKey = oldVersionKey
        newVersionKey = newVerkey
        '''
        while oldVersionKey == newVersionKey:
            newVersionKey = self.group.random()
        authAttrs[attribute]['VK'] = newVersionKey
        '''
        
        u_uid = userObj['sk']
        UKs = GPP['H'](attribute) ** (ASK['beta'] * (newVersionKey - oldVersionKey) * (u_uid + ASK['gamma']))
        UKc = (newVersionKey/oldVersionKey, (oldVersionKey - newVersionKey)/(oldVersionKey * ASK['gamma']))
        '''
        authAttrs[attribute]['PK1'] = authAttrs[attribute]['PK1'] ** UKc[0]
        authAttrs[attribute]['PK2'] = authAttrs[attribute]['PK2'] ** UKc[0]
        '''

        return { 'UKs': UKs, 'UKc': UKc }

    
    def skupdate(self, USK, attribute, UKs):
        '''Updates the user attribute secret key for the specified attribute (executed by non-revoked user)'''
        USK['AK'][attribute] = USK['AK'][attribute] * UKs

    
    def ctupdate(self, GPP, CT, attribute, UKc):
        '''Updates the cipher-text using the update key, because of the revoked attribute (executed by cloud provider)'''
        CT['C'][attribute] = CT['C'][attribute] * (CT['DS'][attribute] ** UKc[1])
        CT['DS'][attribute] = CT['DS'][attribute] ** UKc[0]


def Deserialize_user_info(jsUser):
    #info gom uid, verify code, tap thuoc tinh
    user = {}
    user ['uid'] = jsUser['uid']  #jsUser['uid']
    user['attributes'] = jsUser['attributes'] #jsUser ['attributes']
    # print("user_info: ",user)
    return user

def serialize_aa_SK(SKa):
    jsSKa = {
        'alpha': groupObj.serialize(SKa['alpha']).decode(),
        'beta': groupObj.serialize(SKa['beta']).decode(),
        'gamma': groupObj.serialize(SKa['gamma']).decode()
    }
    return jsSKa
def deserialize_aa_SK(jsSKa):
    SKa = {
        'alpha': groupObj.deserialize(jsSKa['alpha'].encode()),
        'beta': groupObj.deserialize(jsSKa['beta'].encode()),
        'gamma': groupObj.deserialize(jsSKa['gamma'].encode())
    }
    return SKa

def serialize_aa_PK(PKa,authAttrs):
    #authorityAttributes = ['HEAD-DIRECTOR', 'DIVISIONAL MANAGEMENT', 'CEO', 'CTO', 'CIO', 'BRANCH MANANGER', 'ASSISTANT OF BM', 'CUSTOMER SERVICE', 'RELATIONSHIP MANAGEMENT', 'CONSULTANT', 'CENTRAL', 'PROV1', 'PROV2', 'PROV3', 'PROV4', 'PROV5']
     
    PK1 = {
        'e_alpha': groupObj.serialize(PKa['e_alpha']).decode() ,
        'g_beta':groupObj.serialize(PKa['g_beta']).decode(),
        'g_beta_inv': groupObj.serialize(PKa['g_beta_inv']).decode()
    }

    PK_do = {} 
    for attrib in authAttrs:        
        VK = groupObj.serialize(authAttrs[attrib]['VK'])
        PK1 = groupObj.serialize(authAttrs[attrib]['PK1'])
        PK2 = groupObj.serialize(authAttrs[attrib]['PK2'])
        PK_do[attrib]= {'VK': VK.decode(), 'PK1': PK1.decode(), 'PK2': PK2.decode()}
    
    jsAuthority = {
        'PK': ({}, PK1, PK_do),
        'authr':authAttrs
    }

    return jsAuthority

def deserialize_aa_PK(jsPKa):
    #authorityAttributes = ['HEAD-DIRECTOR', 'DIVISIONAL MANAGEMENT', 'CEO', 'CTO', 'CIO', 'BRANCH MANANGER', 'ASSISTANT OF BM', 'CUSTOMER SERVICE', 'RELATIONSHIP MANAGEMENT', 'CONSULTANT', 'CENTRAL', 'PROV1', 'PROV2', 'PROV3', 'PROV4', 'PROV5']
    _PKa, _authAttrs = jsPKa["PK"][1], jsPKa["PK"][2]
    PKa = {
        'e_alpha': groupObj.deserialize(_PKa['e_alpha'].encode()),
        'g_beta': groupObj.deserialize(_PKa['g_beta'].encode()),
        'g_beta_inv': groupObj.deserialize(_PKa['g_beta_inv'].encode())
    }

    authAttrs = {}
    for attrib in _authAttrs:
        authAttrs[attrib] = {}
        authAttrs[attrib] = {
            'VK': groupObj.deserialize(_authAttrs[attrib]['VK'].encode()),
            'PK1': groupObj.deserialize(_authAttrs[attrib]['PK1'].encode()),
            'PK2': groupObj.deserialize(_authAttrs[attrib]['PK1'].encode())
        }

    return PKa, authAttrs


def Deserialize_user_publickeyABE (jsUPK):
    UPK = {}
    UPK['uid'] = jsUPK['uid']
    UPK = {
        'pk': groupObj.deserialize(jsUPK['uPK']['pk'].encode()),
        'sk': groupObj.deserialize(jsUPK['uPK']['sk'].encode())

    }
    

    return UPK


def Serialize_User_USK_Update(USK):
    jsUSK = {}
    jsUSK = {
        'K': groupObj.serialize(USK['K']).decode(),
        'KS': groupObj.serialize(USK['KS']).decode()
    }
    attrs = list(USK['AK'].keys())
    jsUSK ['AK'] = {}
    for attr in attrs:
        jsUSK['AK'][attr] = groupObj.serialize(USK['AK'][attr]).decode()
    return  jsUSK


def Deserialize_user_secretkeyABE(jsUSK):
    USK = {}
    USK = {
        'K': groupObj.deserialize(jsUSK['K'].encode()),
        'KS': groupObj.deserialize(jsUSK['KS'].encode())
    }
    attrs = list(jsUSK['AK'].keys())
    USK['AK'] = {}
    for attr in attrs:
        USK['AK'][attr] = groupObj.deserialize(jsUSK['AK'][attr].encode())
    return  USK


if __name__ == "__main__":
    import json
    import os
    import pickle
    import uuid
    from pwn import remote
    debug = False
    groupObj = PairingGroup('SS512')
    maabe = MAABE(groupObj=groupObj)
    print("----RUNNING REVOVKE PHASE----")
    directory = '/home'
    prefix = 'user'
    list_user = []
    for root, dirs, files in os.walk(directory):
        for dir in dirs:
            if dir.startswith(prefix):
                uid = dir.split('-')[1]
                list_user.append(uid)
                print("User ID: ", uid)
    
    #
    list_attr = []
    revoke_uid = input("Choose user to revoke attribute: ").strip()
    #print(revoke_uid)
    revoke_attr = ""
    if os.path.isfile(f"/home/user-{revoke_uid}/attributes.json"):
        print("Choose the below attribute to revoke: ")
        with open(f"/home/user-{revoke_uid}/attributes.json", "r") as f:
            jsInfo = json.load(f)
            jsInfo = Deserialize_user_info(jsInfo)
            list_attr = jsInfo['attributes']
            for attr in list_attr:
                print(attr)
        f.close()
        revoke_attr = input(">> ").strip()
    else:
        print("User not found!")
        exit(0)
    if os.path.isfile("global-params.json"):   
        with open("global-params.json", "r") as f:
            jsGPP = json.load(f)
        f.close()

        GPP = {'g': groupObj.deserialize(jsGPP['g'].encode()),
                'g_a': groupObj.deserialize(jsGPP['g_a'].encode()),
                'g_b': groupObj.deserialize(jsGPP['g_b'].encode())}
        H = lambda x: groupObj.hash(x, G1)
        GPP['H'] = H
    with open("aa-privatekeyabe.json") as f:
        SKa = json.load(f)
    f.close()

    with open("aa-publickeyabe.json") as f:
        PKa = json.load(f)
    f.close()

    SKa = deserialize_aa_SK(SKa)
    PKa, authAttrs = deserialize_aa_PK(PKa)
    
    
    auth = SKa, PKa, authAttrs
    newVersionKey = authAttrs[f'{revoke_attr}']['VK']
    while newVersionKey == authAttrs[f'{revoke_attr}']['VK']:
        newVersionKey = maabe.group.random()
    UK = {}
    for uid in list_user:
        if(uid != revoke_uid):
            jsUPK = {}
            UPK = {}
            if os.path.exists(f"/home/user-{uid}/user-secretkeyabe-{uid}.json"):
                with open(f"/home/user-{uid}/user-publickeyabe-{uid}.json", "r") as f:
                    jsUPK = json.load(f)
                    UPK = Deserialize_user_publickeyABE (jsUPK)
                f.close()
                UK = maabe.ukeygen(GPP, auth, revoke_attr, UPK, newVersionKey)
                #UKA = maabe.ukeygen(GPP, authorities[authority1], attribute, users[alice['id']],newVersionKey)
                
                jsUSK = {}
                USK = {}
                with open(f"/home/user-{uid}/user-secretkeyabe-{uid}.json", "r") as f:
                    jsUSK = json.load(f)
                    print(jsUSK)
                    USK = Deserialize_user_secretkeyABE(jsUSK)
                f.close()

                maabe.skupdate(USK, revoke_attr, UK['UKs'])
                jsUSK = Serialize_User_USK_Update(USK)
                with open(f"/home/user-{uid}/user-secretkeyabe-{uid}.json", "w") as f:
                    json.dump(jsUSK,f)                
                f.close()


    #auth[f'{revoke_attr}']['VK'] = newVersionKey
    #auth[f'{revoke_attr}']['PK1'] = auth['ONE']['PK1']  ** UK['UKc'][0]
    #auth[f'{revoke_attr}']['PK2'] = auth['ONE']['PK2'] ** UK['UKc'][0]
    authAttrs[f'{revoke_attr}']['VK'] = newVersionKey
    authAttrs[f'{revoke_attr}']['PK1'] = authAttrs[f'{revoke_attr}']['PK1'] ** UK['UKc'][0]
    authAttrs[f'{revoke_attr}']['PK2'] = authAttrs[f'{revoke_attr}']['PK2'] ** UK['UKc'][0]

    jsSKa = serialize_aa_SK(SKa)
    with open("aa-privatekeyabe.json", "w") as f:
        json.dump(jsSKa, f)
    f.close()

    jsPKa = serialize_aa_PK(PKa,authAttrs)
    print (jsPKa)
    #with open("aa-publickeyabe.json", "w") as f:
    #    json.dump(jsPKa,f)
    #f.close()

    #send UKc to bank-server-app to update:
    #ser_UKc = ()
    #ser_UKc[0] = groupObj.serialize(UK['UKc'][0]).decode()
    #ser_UKc[1] = groupObj.serialize(UK['UKc'][1]).decode()
    ser_UKc = []
    ser_UKc.append(groupObj.serialize(UK['UKc'][0]).decode())
    ser_UKc.append(groupObj.serialize(UK['UKc'][1]).decode())
    ser_UKc.append(revoke_attr)

    jsUKc = { "UKc": ser_UKc }
    with open ("/home/attr-auth/updatekey_cloud.json", "w") as f:
        json.dump(jsUKc,f)
    f.close()

    context.log_level = 'Debug'
    s = remote("bank-server-app", 1334)  
    with open ("/home/attr-auth/updatekey_cloud.json", "rb") as f:
        s.sendlineafter(b"Input updatekey_cloud: ", f.read())
    s.close()
     

    

    





    
    

    

    
    
    
    
    
