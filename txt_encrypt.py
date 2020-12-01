import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

actual_password = "csc332Crypto<3" #this is the string form of the password
password = actual_password.encode() #converts the string to a bytes object

#b is to know that its bits
#pads the password with extra bits
#there is a function to create random salts
salt = b'qQqbHctmkCEdh_RFhvIy5Qg5yPSDeEFpNnyThdGgM3c='

#all in one method
#derives the key of a given length, salt, and the number of iterations
#is hashed using SHA-256 hash fuction

#HMAC - if a key is longer than the block size of the hash function
#it uses the hash of the key as the actual key
#rather than the derived key
kdf = PBKDF2HMAC(
algorithm = hashes.SHA256(),
length=32,
salt = salt,
iterations = 100000,
backend=default_backend()
)

#encodes the key in base 64
key = base64.urlsafe_b64encode(kdf.derive(password)) #only uses kdf once


#writing the key to a text file
#we need to save the key so we can use the same key to decrypt
file = open('hashtest2.txt', 'w') #keeping type bit
file.write(str(key))
file.close()

#getting the key
#file2 = open('hashtest1.txt', 'rb')
#file2.read()
#file.close()

