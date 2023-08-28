from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import random
from base64 import b64encode
import json

#---------- step 1 and 2 ---------# RSA

random_number = random.randint(10**15, (10**16)-1)
RANDOMNO = str(random_number).zfill(16)

key = RSA.generate(4096)

public_key = key.publickey().export_key()

cipher = PKCS1_v1_5.new(key)
encrypted_data = cipher.encrypt(RANDOMNO.encode('utf-8'))

encoded_data = base64.b64encode(encrypted_data)

encryptedKey = encoded_data.decode('utf-8')
print("encryptedKey", encryptedKey)


#---------------- step 3 -----------# AES

sample_data = b"secret"

key = RANDOMNO.encode('utf-8')

cipher = AES.new(key, AES.MODE_CBC)
ciphertext_bytes = cipher.encrypt(pad(sample_data, AES.block_size))
iv = b64encode(cipher.iv).decode('utf-8')
encryptedData = b64encode(ciphertext_bytes).decode('utf-8') # cipher text

#----------------- Output -----------#

byte_iv = b64encode(cipher.iv)
IV = byte_iv
byte_cipher = b64encode(encrypted_data)
concatB = byte_iv + byte_cipher
encryptedData2 = b64encode(concatB)

encryptedDatafinal = b64encode(concatB).decode('utf-8')

enc_dict = {"encryptedKey": encryptedKey, "iv": IV, "encryptedData": encryptedDatafinal}
print(enc_dict)