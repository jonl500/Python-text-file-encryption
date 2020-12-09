import os
import json
import hashlib
from os import listdir
from os.path import isfile, join
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


def passCheck(user_input):
    pass_file = open('passgen.txt', 'rb')
    storage = pass_file.read()
    salt_from_storage = storage[:32]  # 32 is the length of the salt
    key_from_storage = storage[32:]
    new_key = hashlib.pbkdf2_hmac('sha256', user_input.encode('utf-8'), salt_from_storage, 100000)
    if new_key == key_from_storage:
        print('Password is correct')
        return True
    else:
        print('Password is incorrect')
        return False
def encrypt(fileName, privKey):
    base = os.path.basename(fileName)
    name = os.path.splitext(base)[0]
    with open(fileName, 'r') as f:
        text = f.read()
    f.close()
    data = bytes(text, 'utf-8')
    key = get_random_bytes(16)
    with open(privKey + '.txt', 'wb') as f:
        f.write(key)
    f.close()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    info = {
        'iv': iv,
        'ciphertext': ct
    }
    with open(name + '.json', 'w') as file:
        json.dump(info, file, indent = 4)
    file.close()
    os.remove(base)
# We assume that the key was securely shared beforehand
def decrypt(fileName, privKey):
    try:
        base = os.path.basename(fileName)
        keyBase = os.path.basename(privKey)
        with open(base , 'r') as myfile:
            a = myfile.read()
        b64 = json.loads(a)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        myfile.close()
        with open(keyBase, 'rb') as f:
            key = f.read()
        f.close()
        os.remove(keyBase)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt.decode('utf-8'))
        name = os.path.splitext(base)[0]
        newPlainTxt = open(name + '.txt', 'w')
        newPlainTxt.write(pt.decode('utf-8'))
        newPlainTxt.close()
        os.remove(base)
    except ValueError as KeyError:
        print("Incorrect decryption")

# password = input("Please input password to access encryption program: ")
#
# if (passCheck(password) == True):
#
#     command = input("choose encrypt or decrypt: ")
#     if (command == "encrypt"):
#
#         file_name = input('Input a text file: ')
#
#         prKey = input("Give a name to your key file: ")
#
#         with open(file_name, 'r') as f:
#             text = f.read()
#             encrypt(file_name, prKey)
#
#         f.close()
#
#
#     elif(command == "decrypt"):
#         file_name = input('Input a json file: ')
#         #dir = input('Type in a directory: ')
#         keyName = input("type keyfile name here: ")
#         #keydir = input('Type in a directory for your key: ')
#         #if os.path.exists(dir) & os.path.exists(keydir):
#         with open(file_name, 'r') as f:
#                 text = f.read()
#                 decrypt(file_name,keyName)
#         f.close()
#         # else:
#         #    print('The directory does not exist, please try again.')
# else:
#     print("Password incorrect!")