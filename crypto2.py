import hashlib
import base64
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
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


def encrypt(plain_text):
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
        }
    file = open('encrypted_text.txt', 'wb')
    file.write(cipher_text)
    file.close()


#pattern matching
if private_key == hashed_password:
    print("Success!")
    plain_text = input("plain text here:")
    encrypt(plain_text)
else :
   print('Fail :(')

