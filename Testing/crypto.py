import hashlib
import base64
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

actual_password = "csc332Crypto<3" #this is the string form of the password
# password = actual_password.encode() #converts to bytes

#b is to know that its bits
#pads the password with extra bits
salt = b'qQqbHctmkCEdh_RFhvIy5Qg5yPSDeEFpNnyThdGgM3c='

#all in one method

# kdf = PBKDF2HMAC(
# algorithm = hashes.SHA256(),
# length=32,
# salt = salt,
# iterations = 100000,
# backend=default_backend()
# )

private_key = hashlib.scrypt(
        actual_password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


#key = base64.urlsafe_b64encode(kdf.derive(password)) #only uses kdf once
print(private_key)
file = open('hashtest1.txt', 'wb')
file.write(private_key)
file.close()

# with open('hashtest1.txt','r') as file:
#     hashed_password = file.read()
# print(hashed_password)
#
# if hashed_password == open('hashtest1.txt').read():
#     print("Success!")
# else :
#     print("Fail :(")
