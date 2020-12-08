import os
import hashlib
import base64


password = 'csc332Crypto<3' # The users password

salt = os.urandom(32) # A new salt for this user
key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
# Store them as:
storage = salt + key
file = open('passgen.txt', 'wb')
file.write(storage)
file.close()
# Getting the values back out
salt_from_storage = storage[:32] # 32 is the length of the salt
key_from_storage = storage[32:]
