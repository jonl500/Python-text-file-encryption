import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

actual_password = "csc332Crypto<3" #this is the string form of the passw$
password = input('enter password: ')
password2 = password.encode()
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

key = base64.urlsafe_b64encode(kdf.derive(password2))

with open('hashtest1.txt','rb') as file:
    hashed_password = file.read()
print(hashed_password)

if key == hashed_password:
    print("Success!")
else :
   print('Fail :(')
