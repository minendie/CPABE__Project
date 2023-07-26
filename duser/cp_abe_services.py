from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import os
import json


groupObj = PairingGroup('SS512')


class MAABE(object):
    
    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)  #Create Secret Sharing Scheme
        self.group = groupObj    #:Prime order group
    
    def encrypt(self, GPP, policy_str, k, authority):
        '''Generate the cipher-text from the content(-key) and a policy (executed by the content owner)'''
        #GPP are global parameters
        #k is the content key (group element based on AES key)
        #policy_str is the policy string
        #authority is the authority tuple
        
        _, APK, authAttrs = authority# receive from Authority_enc.json
        
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
    
    def ctupdate(self, GPP, CT, attribute, UKc):
        '''Updates the cipher-text using the update key, because of the revoked attribute (executed by cloud provider)'''
        CT['C'][attribute] = CT['C'][attribute] * (CT['DS'][attribute] ** UKc[1])
        CT['DS'][attribute] = CT['DS'][attribute] ** UKc[0]
        return CT


def deserialize_AA_PK(jsAuth):
    print(jsAuth)
    auth_attributes = jsAuth['auth']
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


def deserialize_GPP(jsGPP):
    # GPP nhận GPP từ CA 
    # -----------------------------------   
    GPP = {}
    H = lambda x: groupObj.hash(x, G1)
    GPP = {'g': groupObj.deserialize(jsGPP['g'].encode()),
            'g_a': groupObj.deserialize(jsGPP['g_a'].encode()),
            'g_b': groupObj.deserialize(jsGPP['g_b'].encode()),
            }
    GPP['H'] = H
    return GPP


def serialize_ciphertext(CP):
    jsCP = {}
    jsCP = {
        'C1': groupObj.serialize(CP['C1']).decode(),
        'C2': groupObj.serialize(CP['C2']).decode(),
        'C3': groupObj.serialize(CP['C3']).decode()
    }

    tmpC = {}
    tmpCS = {}
    tmpD = {}
    tmpDS = {}
    attrs = list(CP['C'].keys())
    for attrib in attrs:
        tmpC[attrib] = (groupObj.serialize(CP['C'][attrib]).decode())
        tmpCS[attrib] = (groupObj.serialize(CP['CS'][attrib]).decode())
        tmpD[attrib] = (groupObj.serialize(CP['D'][attrib]).decode()) 
        tmpDS[attrib] = (groupObj.serialize(CP['DS'][attrib]).decode())
    jsCP['C'] = tmpC
    jsCP['CS'] = tmpCS
    jsCP['D'] = tmpD
    jsCP['DS'] = tmpDS
    jsCP['policy'] = CP['policy']   
    sr_ciphertext = json.dumps(jsCP)
    #print(type(sr_ciphertext))
    return sr_ciphertext


def deserialize_ciphertext(strCP):
    jsCP = {}
    jsCP = json.loads(strCP)
    dr_key = {
        'C1': groupObj.deserialize(jsCP['C1'].encode()),
        'C2': groupObj.deserialize(jsCP['C2'].encode()),
        'C3': groupObj.deserialize(jsCP['C3'].encode())
    }
    
    tmpC = {}
    tmpCS = {}
    tmpD = {}
    tmpDS = {}
    attrs = list(jsCP['C'].keys())
    for attrib in attrs:
        tmpC[attrib] = (groupObj.deserialize(jsCP['C'][attrib].encode()))
        tmpCS[attrib] = (groupObj.deserialize(jsCP['CS'][attrib].encode()))
        tmpD[attrib] = (groupObj.deserialize(jsCP['D'][attrib].encode())) 
        tmpDS[attrib] = (groupObj.deserialize(jsCP['DS'][attrib].encode()))
    dr_key['C'] = tmpC
    dr_key['CS'] = tmpCS
    dr_key['D'] = tmpD
    dr_key['DS'] = tmpDS
    dr_key['policy'] = jsCP['policy']   
    #print(type(dr_key))
    return dr_key


def encrypt_content_key(key, policy_str):
    # key pairing group GT
    maabe = MAABE(groupObj=groupObj)
    jsAuth = {}
    if os.path.isfile("Authority_enc.json"):
        with open("Authority_enc.json", "r") as f:
            jsAuth = json.load(f)
        f.close()
    authority = deserialize_AA_PK(jsAuth) # tuple

    jsGPP = {}
    if os.path.isfile("GlobalParams.json"): #nhan tu CA
        with open ("GlobalParams.json", "r") as f:
            jsGPP = json.load(f)
        f.close()
    GPP = deserialize_GPP(jsGPP)
    k = maabe.encrypt(GPP, policy_str, key, authority)
    k = serialize_ciphertext(k) # convert k to string
    #print(k)
    return k


def ct_update(CT ): #CT is <string> this function use by encrypt_services to request old CT -> update CT
    maabe = MAABE(groupObj=groupObj)
    #desrialize UKc
    CT = deserialize_ciphertext(CT)
    jsUKc = {}
    if os.path.isfile("UpdateKey_Cloud.json"): #nhan tu AA khi revoke 
        with open ("UpdateKey_Cloud.json", "r") as f:
            jsUKc = json.load(f)
        f.close()
    UKc = []
    UKc.append(jsUKc['UKc'][0])
    UKc.append(jsUKc['UKc'][1])
    attr_revoke = jsUKc['UKc'][2]
    # deserialize
    UKc[0] = groupObj.deserialize(UKc[0].encode())
    UKc[1] = groupObj.deserialize(UKc[1].encode())
    GPP = {}
    CT= maabe.ctupdate(GPP,CT,attr_revoke,UKc)
    CT = serialize_ciphertext(CT)
    return CT


def Test():
    print("You're runining Test encrypt content key k:")
    k = groupObj.random(GT)
    policy_str = '((HEAD-DIRECTOR or CIO) and (CENTRAL or PROV5))'
    key = encrypt_content_key(k,policy_str) #str
    #print(deserialize_ciphertext(key))
    
    

# Test()
    
    
