import os
import json
from os import listdir
from os.path import isfile, join
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

def encrypt(data):
    data = bytes(data, 'utf-8')
    key = get_random_bytes(16)
    with open('dataKey.txt', 'wb') as f:
        f.write(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    info = {
        'iv': iv,
        'ciphertext': ct
    }
    with open('data.json', 'w') as file:
        json.dump(info, file, indent = 4)

# We assume that the key was securely shared beforehand
def decrypt():
    try:
        with open('data.json', 'r') as myfile:
            a = myfile.read()
        b64 = json.loads(a)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        with open('dataKey.txt', 'rb') as f:
            key = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt.decode('utf-8'))
    except ValueError as KeyError:
        print("Incorrect decryption")

file_name = input('Input a text file: ')
dir = input('Type in a directory: ')

if(os.path.exists(dir)):
   with open(file_name, 'r') as f:
        text = f.read()
        encrypt(text)
        os.remove(file_name)
        decrypt()
   f.close()
else:
   print('The directory does not exist, please try again.')
