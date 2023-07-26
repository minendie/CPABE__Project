import os
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding

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


def basicTest():
    print("RUN basicTest")
    groupObj = PairingGroup('SS512')
    maabe = MAABE(groupObj)
    GPP, GMK = maabe.setup()
    
    users = {} # public user data
    authorities = {}
    
    authorityAttributes = ["ONE", "TWO", "THREE", "FOUR"]
    authority1 = "authority1"
    
    maabe.setupAuthority(GPP, authority1, authorityAttributes, authorities)
    
    alice = { 'id': 'alice', 'authoritySecretKeys': {}, 'keys': None }
    alice['keys'], users[alice['id']] = maabe.registerUser(GPP)
    
    for attr in authorityAttributes[0:-1]:
        maabe.keygen(GPP, authorities[authority1], attr, users[alice['id']], alice['authoritySecretKeys'])
    
    k = groupObj.random(GT)
    
    policy_str = '((ONE or THREE) and (TWO or FOUR))'
    
    CT = maabe.encrypt(GPP, policy_str, k, authorities[authority1])
    
    PT = maabe.decrypt(GPP, CT, alice)
    
    # print "k", k
    # print "PT", PT
    
    assert k == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')


def revokedTest():
    print("RUN revokedTest")
    groupObj = PairingGroup('SS512')
    maabe = MAABE(groupObj)
    GPP, GMK = maabe.setup()
    
    users = {} # public user data
    authorities = {}
    
    authorityAttributes = ["ONE", "TWO", "THREE", "FOUR"]
    authority1 = "authority1"
    
    maabe.setupAuthority(GPP, authority1, authorityAttributes, authorities)
    
    alice = { 'id': 'alice', 'authoritySecretKeys': {}, 'keys': None }
    alice['keys'], users[alice['id']] = maabe.registerUser(GPP)
    
    bob = { 'id': 'bob', 'authoritySecretKeys': {}, 'keys': None }
    bob['keys'], users[bob['id']] = maabe.registerUser(GPP)
    
    for attr in authorityAttributes[0:-1]:
        maabe.keygen(GPP, authorities[authority1], attr, users[alice['id']], alice['authoritySecretKeys'])
        maabe.keygen(GPP, authorities[authority1], attr, users[bob['id']], bob['authoritySecretKeys'])
    
    k = groupObj.random(GT)
    
    policy_str = '((ONE or THREE) and (TWO or FOUR))'
    
    CT = maabe.encrypt(GPP, policy_str, k, authorities[authority1])
    
    PT1a = maabe.decrypt(GPP, CT, alice)
    PT1b = maabe.decrypt(GPP, CT, bob)
    
    assert k == PT1a, 'FAILED DECRYPTION (1a)!'
    assert k == PT1b, 'FAILED DECRYPTION (1b)!'
    print('SUCCESSFUL DECRYPTION 1')
    
    # revoke bob on "ONE"
    attribute = "ONE"
    UK = maabe.ukeygen(GPP, authorities[authority1], attribute, users[alice['id']])
    maabe.skupdate(alice['authoritySecretKeys'], attribute, UK['UKs'])
    maabe.ctupdate(GPP, CT, attribute, UK['UKc'])
    
    PT2a = maabe.decrypt(GPP, CT, alice)
    PT2b = maabe.decrypt(GPP, CT, bob)
    
    assert k == PT2a, 'FAILED DECRYPTION (2a)!'
    assert k != PT2b, 'SUCCESSFUL DECRYPTION (2b)!'
    print('SUCCESSFUL DECRYPTION 2')


def test():
    groupObj = PairingGroup('SS512')


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
    
    # print ("GPP: ", GPP)
    return GPP


def Deserialize_user_info(jsUser):
    #info gom uid, verify code, tap thuoc tinh
    user = {}
    user ['uid'] = jsUser['uid']  #jsUser['uid']
    user['attributes'] = jsUser['attributes'] #jsUser ['attributes']
    # print("user_info: ",user)
    return user
    

def Deserialize_user_CA(uid: str):
    user_pub_CA = {}
    jsUP = {}
    if os.path.isfile(f"/home/user-{uid}/user-publickeyabe-{uid}.json"):
        with open(f"/home/user-{uid}/user-publickeyabe-{uid}.json", "r") as f:
            jsUP = json.load(f)
        f.close()
               
    
        user_pub_CA ['uid'] = uid # jsUP['uid']
        user_pub_CA['uPK'] = {
            'pk': groupObj.deserialize(jsUP['uPK']['pk'].encode()),
            'sk': groupObj.deserialize(jsUP['uPK']['sk'].encode()) 
        }

   
    return user_pub_CA


def deserialize_aa_SK(jsSKa):
    SKa = {
        'alpha': groupObj.deserialize(jsSKa['alpha'].encode()),
        'beta': groupObj.deserialize(jsSKa['beta'].encode()),
        'gamma': groupObj.deserialize(jsSKa['gamma'].encode())
    }
    return SKa


def deserialize_aa_PK(jsPKa):
    authorityAttributes = ['HEAD-DIRECTOR', 'DIVISIONAL MANAGEMENT', 'CEO', 'CTO', 'CIO', 'BRANCH MANANGER', 'ASSISTANT OF BM', 'CUSTOMER SERVICE', 'RELATIONSHIP MANAGEMENT', 'CONSULTANT', 'CENTRAL', 'PROV1', 'PROV2', 'PROV3', 'PROV4', 'PROV5']
    _PKa, _authAttrs = jsPKa["PK"][1], jsPKa["PK"][2]
    PKa = {
        'e_alpha': groupObj.deserialize(_PKa['e_alpha'].encode()),
        'g_beta': groupObj.deserialize(_PKa['g_beta'].encode()),
        'g_beta_inv': groupObj.deserialize(_PKa['g_beta_inv'].encode())
    }

    authAttrs = {}
    for attrib in _authAttrs:
        authAttrs[attrib] = {
            'PK1': groupObj.deserialize(_authAttrs[attrib]['PK1'].encode()),
            'PK2': groupObj.deserialize(_authAttrs[attrib]['PK1'].encode())
        }

    return PKa, authAttrs


if __name__ == "__main__":
    import json
    import os
    import pickle
    import uuid
    debug = False

    groupObj = PairingGroup('SS512')
    maabe = MAABE(groupObj=groupObj)

    with open ("global-params.json", "r") as f:
        jsGPP = json.load(f)
    f.close()

    GPP = Deserialize_GPP(jsGPP)

    uid = input("uid: ")

    if not os.path.exists(f"/home/user-{uid}"):
        print("User does not exist")
        #exit(0)

    with open("aa-privatekeyabe.json") as f:
        SKa = json.load(f)
    f.close()

    with open("aa-publickeyabe.json") as f:
        PKa = json.load(f)
    f.close()

    SKa = deserialize_aa_SK(SKa)
    PKa, authAttrs = deserialize_aa_PK(PKa)

    user_info = input("user_info: ")

    jsUser = json.loads(user_info)    
    #print(jsUser)
    if not os.path.isfile(f"/home/user-{uid}/attributes.json"):
        with open(f"/home/user-{uid}/attributes.json", "w") as f:
            json.dump(jsUser,f)
        f.close()
    
    user_ = Deserialize_user_info(jsUser)
    
    auth = SKa, PKa, authAttrs

    user_pub_CA = Deserialize_user_CA(uid)

    # secret key cho decrypt
    USK = {}
    jsUSK = {}
    tmpAK = {}    
    for attr in user_['attributes']:  
        #maabe.keygen(GPP, authorities[authority1], attr, users[alice['id']], alice['authoritySecretKeys'])            
        USK = maabe.keygen(GPP, auth, attr, user_pub_CA['uPK'], None)  
        tmpAK[attr] = groupObj.serialize(USK['AK'][attr]).decode()
       
    if not os.path.isfile(f"/home/user-{uid}/user-sercetkeyabe-{uid}.json"):
        jsUSK = {
            'K': groupObj.serialize(USK['K']).decode(),
            'KS': groupObj.serialize(USK['KS']).decode()
        }

        for i in range(0,len(tmpAK)):
            jsUSK['AK'] = tmpAK
        
        with open(f"/home/user-{uid}/user-secretkeyabe-{uid}.json", "w") as f:
            json.dump(jsUSK, f)
        f.close()
    
    with open(f"/home/user-{uid}/user-secretkeyabe-{uid}.json") as f:
        print(f.read())
    f.close()