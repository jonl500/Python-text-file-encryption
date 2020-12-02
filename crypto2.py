import hashlib
import base64
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import csv
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

password = input('enter password: ')

salt = b'qQqbHctmkCEdh_RFhvIy5Qg5yPSDeEFpNnyThdGgM3c='

#all in one method

# kdf = PBKDF2HMAC(
# algorithm = hashes.SHA256(),
# length=32,
# salt = salt,
# iterations = 100000,
# backend=default_backend()
#)

#encode password
#key = base64.urlsafe_b64encode(kdf.derive(password2))
private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

with open('hashtest1.txt','rb') as file:
    hashed_password = file.read()


def encrypt(plain_text,password):
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
        }
    file = open('encrypted.txt', 'w')
    file.write(cipher_text)
    file.close()

def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])


    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted

    #pattern matching
if private_key == hashed_password:
    print("Success!")
    x = input("encrypt or decrypt? ")

    if  x == "encrypt":
        plain_text = input("plain text here:")
        encrypt(plain_text, hashed_password)
    elif x == "decrypt":
        print("decription")    
else :
    print('Fail :(')

