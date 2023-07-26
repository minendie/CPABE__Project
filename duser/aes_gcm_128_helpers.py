from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def encrypt_AES_GCM(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    #attach nonce+tag with ciphertext
    return ciphertext + cipher.nonce + tag


def decrypt_AES_GCM(raw_ciphertext, key):
    # split nonce and tag from cipher
    ciphertext = raw_ciphertext[:len(raw_ciphertext)-32]
    temp_ = raw_ciphertext[len(ciphertext):]
    nonce = temp_[:16]
    tag = temp_[16:]
    # decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext


