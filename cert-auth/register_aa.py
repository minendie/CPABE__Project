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
        #H_serialize = pickle.dumps(H)
        a = self.group.random()
        b = self.group.random()
        g_a = g ** a
        g_b = g ** b
        GPP = {'g': g, 'g_a': g_a, 'g_b': g_b, 'H': H}#_serialize}
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


if __name__ == '__main__':
    import json
    import os
    import uuid    
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from pki_helpers import sign_csr
    from pwn import remote, context


    context.log_level = 'Debug'
    
    groupObj = PairingGroup('SS512')
    maabe = MAABE(groupObj=groupObj)
    
    
    if not os.path.isfile("global-params.json") and not os.path.isfile("global-master.json"):   
        GPP, GMK = maabe.setup()
        #print(type(groupObj.serialize(GPP['g']).decode()))
        jsGPP = {'g': groupObj.serialize(GPP['g']).decode(),
                 'g_a': groupObj.serialize(GPP['g_a']).decode(),
                 'g_b': groupObj.serialize(GPP['g_b']).decode(),
                  }

        jsGMK = {'a': groupObj.serialize(GMK['a']).decode(), 
                 'b': groupObj.serialize(GMK['b']).decode()}

        with open("global-params.json", "w") as f:
            json.dump(jsGPP, f)
        f.close()

        with open("global-master.json", "w") as f:
            json.dump(jsGMK, f)
        f.close()
    else:
        with open("global-params.json", "r") as f:
            jsGPP = json.load(f)
        f.close()

        with open("global-master.json", "r") as f:
            jsGMK = json.load(f)
        f.close()

        # H = lambda x: groupObj.hash(x, G1)
        GPP = {'g': groupObj.deserialize(jsGPP['g'].encode()),
               'g_a': groupObj.deserialize(jsGPP['g_a'].encode()),
               'g_b': groupObj.deserialize(jsGPP['g_b'].encode()),
                }
        # GPP['H'] = H
        
        GMK = {'a': groupObj.deserialize(jsGMK['a'].encode()),
               'b': groupObj.deserialize(jsGMK['b'].encode())}
        
        # print(GPP, GMK)
        
        # receive certificate request signing (CSR)
        certificate = []
        while True:
            line = input("Input: ")
            if line != '':
                #print(line)
                certificate.append(line)
            else:
                break

        certificate = '\n'.join(certificate)

        #AA register:
        # AA = {}
        # AA['aid'] = uuid.uuid4().hex # send to aid
        
        aid = uuid.uuid4().hex

        # Send authority id
        print(f"aid: {aid}")

        # Send global parameters
        with open("global-params.json") as f:
            print(f.read())
        f.close()

        if not os.path.exists(f"/home/aa-{aid}"):
            os.mkdir(f"/home/aa-{aid}")

        if not os.path.isfile(f"/home/aa-{aid}/aa-csr-{aid}.pem"):
            with open(f"/home/aa-{aid}/aa-csr-{aid}.pem", "w") as f:
                f.write(certificate)
            f.close()

        # sign certificate
        csr_file = open(f"/home/aa-{aid}/aa-csr-{aid}.pem", "rb")
        csr = x509.load_pem_x509_csr(csr_file.read(), backend=default_backend())

        ca_public_key_file = open("ca-public-key.pem", "rb")
        ca_public_key = x509.load_pem_x509_certificate(
            ca_public_key_file.read(),
            backend=default_backend()
        )

        ca_private_key_file = open("ca-private-key.pem", "rb")
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_file.read(),
            #b'secret_password',
            password=None,
            backend=default_backend()
        )

        sign_csr(csr, ca_public_key, ca_private_key, f"/home/aa-{aid}/aa-public-key-{aid}.pem")

        # Send certificate
        with open(f"/home/aa-{aid}/aa-public-key-{aid}.pem", "r") as f:
            lines = [line.strip() for line in f.readlines()]
            for line in lines:
                print(line)
        f.close()

        #send ca.pem
        with open(f"/home/cert-auth/ca-public-key.pem", "r") as f:
            lines = [line.strip() for line in f.readlines()]
            for line in lines:
                print(line)
        f.close()

       
        #send log 
        jsLog = {}
        jsLog = {'id': 'cert-auth', 'log': f'Sign certificate for aa-{aid}. Complete register_aa phase.'}
        strLog = json.dumps(jsLog)
        
        s = remote("log_node", 1335)
        s.sendline(strLog.encode('utf-8'))
        s.close()


        


    

