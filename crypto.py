import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

actual_password = "csc332Crypto<3" #this is the string form of the password
password = actual_password.encode() #converts to bytes

#b is to know that its bits
#pads the password with extra bits
salt = b'qQqbHctmkCEdh_RFhvIy5Qg5yPSDeEFpNnyThdGgM3c='

#all in one method

kdf = PBKDF2HMAC(
algorithm = hashes.SHA256(),
length=32,
salt = salt,
iterations = 100000,
backend=default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(password)) #only uses kdf once
#print(key)
file = open('hashtest1.txt', 'wb')
file.write(key)
file.close()

with open('hashtest1.txt','r') as file:
    hashed_password = file.read()
print(hashed_password)

if hashed_password == open('hashtest1.txt').read():
    print("Success!")
else :
    print("Fail :(")
